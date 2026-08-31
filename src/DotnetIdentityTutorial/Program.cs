using DotnetIdentityTutorial.Authorization;
using DotnetIdentityTutorial.Data;
using DotnetIdentityTutorial.ErrorHandling;
using DotnetIdentityTutorial.Filters;
using DotnetIdentityTutorial.Identity;
using DotnetIdentityTutorial.Services.Implementations;
using DotnetIdentityTutorial.Services.Interfaces;
using FluentValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

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

// Discovers every FluentValidation AbstractValidator<T> in this assembly (RoleRequestValidator,
// PermissionRequestValidator, ...) and registers it as IValidator<T> in DI - the global
// ValidationFilter resolves them from there, no per-controller wiring needed.
builder.Services.AddValidatorsFromAssemblyContaining<Program>();

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// Password/lockout policy only - the JWT bearer scheme itself is feature/token-lifecycle's
// job, this branch only needs Identity's own stores and token providers (email confirmation,
// password reset) wired up.
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
})
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders()
    // Replaces Identity's default UserClaimsPrincipalFactory: this is what makes every
    // ClaimsPrincipal Identity builds for a signed-in user also carry one "permission"
    // claim per distinct permission granted by that user's current roles - see
    // ApplicationUserClaimsPrincipalFactory for the actual resolution logic.
    .AddClaimsPrincipalFactory<ApplicationUserClaimsPrincipalFactory>();

builder.Services.AddAuthorization();

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

// AddIdentity<>() above already registers the cookie-based authentication schemes
// Identity needs internally (it calls AddAuthentication for you); this middleware is
// what actually populates HttpContext.User from them on each request, without it
// UseAuthorization below would only ever see an anonymous principal. Registering it
// now, even though no [Authorize] endpoint exists yet, fixes the pipeline order once
// so feature/token-lifecycle doesn't have to remember to insert it in the right spot.
app.UseAuthentication();

app.UseAuthorization();

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
