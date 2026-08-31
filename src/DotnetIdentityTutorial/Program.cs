using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using DotnetIdentityTutorial.Authorization;
using DotnetIdentityTutorial.BackgroundServices;
using DotnetIdentityTutorial.Data;
using DotnetIdentityTutorial.ErrorHandling;
using DotnetIdentityTutorial.Filters;
using DotnetIdentityTutorial.Identity;
using DotnetIdentityTutorial.RateLimiting;
using DotnetIdentityTutorial.Services;
using DotnetIdentityTutorial.Services.Implementations;
using DotnetIdentityTutorial.Services.Interfaces;
using FluentValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

// Types like OpenApiInfo/OpenApiSecurityScheme live directly under Microsoft.OpenApi here,
// not under Microsoft.OpenApi.Models as most Swashbuckle examples show. Swashbuckle.AspNetCore
// 10.x pulls in Microsoft.OpenApi 2.x, which moved the model types and changed how a security
// requirement references a scheme (see the AddSecurityRequirement call below).
using Microsoft.OpenApi;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers(options =>
{
    // Registered globally so no controller needs to call FluentValidation explicitly -
    // see Filters/ValidationFilter.cs.
    options.Filters.Add<ValidationFilter>();
});

// RFC 9457 ProblemDetails for every non-2xx response, paired with GlobalExceptionHandler
// below for exceptions specifically (validation failures are produced natively by
// ASP.NET Core / ValidationFilter without ever throwing).
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();

// TimeProvider: every expiry/lockout/audit timestamp in this project reads the current
// time through this abstraction instead of calling DateTime.UtcNow directly, so tests can
// substitute FakeTimeProvider.
builder.Services.AddSingleton(TimeProvider.System);

builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<IAuditService, AuditService>();
builder.Services.AddScoped<IRbacService, RbacService>();
builder.Services.AddScoped<IUserAdminService, UserAdminService>();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IAuthService, AuthService>();

// Bound once here from the Jwt config section and shared by TokenService (issuance) and the
// TokenValidationParameters below (validation) - see JwtSettings' own remarks for why reading
// the same five keys as independent raw strings in two places was worth consolidating.
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection(JwtSettings.SectionName));
var jwtSettings = builder.Configuration.GetSection(JwtSettings.SectionName).Get<JwtSettings>()
    ?? throw new InvalidOperationException($"Missing or invalid '{JwtSettings.SectionName}' configuration section.");

// Daily housekeeping for RefreshTokens/BlacklistedAccessTokens - see
// ExpiredTokenCleanupService's own remarks for why this is safe to run unconditionally.
builder.Services.AddHostedService<ExpiredTokenCleanupService>();

// Discovers every FluentValidation AbstractValidator<T> in this assembly (RoleRequestValidator,
// PermissionRequestValidator, ...) and registers it as IValidator<T> in DI - the global
// ValidationFilter resolves them from there, no per-controller wiring needed.
builder.Services.AddValidatorsFromAssemblyContaining<Program>();

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// Password/lockout policy, Identity's own stores and token providers (email confirmation,
// password reset), and the custom claims principal factory. AddIdentity internally registers
// its own cookie-based authentication schemes for whatever Identity itself still needs them
// for - the AddAuthentication/AddJwtBearer call below overrides the *default* scheme to JWT
// Bearer without removing those.
builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequiredLength = 8;

    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.AllowedForNewUsers = true;

    // Without this, CheckPasswordSignInAsync would let an account that never completed
    // ConfirmEmail sign in successfully, making the whole activation flow purely cosmetic -
    // SignInResult.IsNotAllowed (mapped to a BusinessRuleException in AuthService.LoginAsync)
    // only reflects this setting when it's explicitly turned on.
    options.SignIn.RequireConfirmedAccount = true;
})
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders()
    // Replaces Identity's default UserClaimsPrincipalFactory: this is what makes every
    // ClaimsPrincipal Identity builds for a signed-in user also carry one "permission"
    // claim per distinct permission granted by that user's current roles - see
    // ApplicationUserClaimsPrincipalFactory for the actual resolution logic.
    .AddClaimsPrincipalFactory<ApplicationUserClaimsPrincipalFactory>();

// JWT Bearer becomes the scheme actually used for [Authorize] on API endpoints - additive to
// the cookie schemes AddIdentity already registered above, not a replacement of them.
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtSettings.Issuer,
            ValidateAudience = true,
            ValidAudience = jwtSettings.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SigningKey)),
            ValidateLifetime = true,
        };

        options.Events = new JwtBearerEvents
        {
            // Access tokens are otherwise validated statelessly - no database round trip at
            // all - except for this one check: a token's jti is checked against
            // BlacklistedAccessToken (via ITokenService, not AppDbContext directly - that
            // ownership stays with TokenService) so an explicit logout takes effect immediately
            // instead of waiting up to Jwt:AccessTokenMinutes for the token to expire on its
            // own. ITokenService is resolved from the request's own scope, not captured from
            // this closure, since this event fires once per request.
            OnTokenValidated = async context =>
            {
                var jti = context.Principal?.FindFirstValue(JwtRegisteredClaimNames.Jti);
                if (string.IsNullOrEmpty(jti))
                {
                    context.Fail("The access token is missing a jti claim.");
                    return;
                }

                var tokenService = context.HttpContext.RequestServices.GetRequiredService<ITokenService>();
                var isBlacklisted = await tokenService.IsAccessTokenBlacklistedAsync(jti, context.HttpContext.RequestAborted);

                if (isBlacklisted)
                {
                    context.Fail("This access token has been revoked.");
                }
            },
        };
    });

builder.Services.AddAuthorization();

// Named policies applied per-action via [EnableRateLimiting("...")] rather than one global
// limit - see RateLimiterPolicies for why Register/Login/ForgotPassword specifically need this
// in addition to Identity's own per-account lockout.
builder.Services.AddRateLimiter(options =>
{
    options.ConfigureRejectionResponse();
    options.AddAuthPolicy();
});

// Replaces the default IAuthorizationPolicyProvider so any [Authorize(Policy = "RESOURCE:ACTION")]
// attribute already sitting on UsersController/RolesController/PermissionsController (added on
// feature/rbac) resolves to a policy on demand instead of failing with "no policy named 'X:Y' was
// found" - see PermissionPolicyProvider. PermissionAuthorizationHandler is the handler that
// actually evaluates the resulting PermissionRequirement against the caller's claims.
builder.Services.AddSingleton<IAuthorizationPolicyProvider, PermissionPolicyProvider>();
builder.Services.AddScoped<IAuthorizationHandler, PermissionAuthorizationHandler>();

var corsAllowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? [];
const string FrontendCorsPolicy = "Frontend";
builder.Services.AddCors(options =>
{
    options.AddPolicy(FrontendCorsPolicy, policy =>
    {
        policy.WithOrigins(corsAllowedOrigins)
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "DotnetIdentityTutorial API",
        Version = "v1",
    });

    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Description = "Enter a valid JWT access token (e.g. \"Bearer {token}\").",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
    });

    // Microsoft.OpenApi 2.x keys a security requirement by a scheme reference resolved
    // against the document being built, not by an inline copy of the scheme object like
    // older Swashbuckle versions expected. The empty scope list is fine here since this is
    // a bearer token, not an OAuth2 flow with scopes.
    options.AddSecurityRequirement(document => new OpenApiSecurityRequirement
    {
        { new OpenApiSecuritySchemeReference("Bearer", document, null), new List<string>() },
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
// UseHttpsRedirection/UseHsts run first, before any other middleware.
app.UseHttpsRedirection();
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

app.UseExceptionHandler();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors(FrontendCorsPolicy);

// Populates HttpContext.User from the default scheme (JWT Bearer, per the
// AddAuthentication(...).AddJwtBearer(...) call above) on each request - without it,
// UseAuthorization below would only ever see an anonymous principal. Identity's own cookie
// schemes stay registered underneath for whatever Identity itself still needs them for.
app.UseAuthentication();

app.UseAuthorization();

// After routing/auth concerns are resolved (so a rate-limited partition can be keyed off
// request state established by then) and before the endpoints it protects actually execute -
// per ASP.NET Core's documented ordering for UseRateLimiter.
app.UseRateLimiter();

app.MapControllers();

// Applying the migration and seeding both run on every startup, not just once manually.
// Migrate() is a no-op once the schema is current, and DbInitializer's steps are
// idempotent (see DbInitializer), so this is safe to call unconditionally instead of
// requiring a reader to run `dotnet ef database update` by hand before `docker-compose up`
// actually works end to end.
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await dbContext.Database.MigrateAsync();

    await DbInitializer.SeedAsync(scope.ServiceProvider);
}

app.Run();
