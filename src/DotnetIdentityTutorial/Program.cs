using DotnetIdentityTutorial.ErrorHandling;
using DotnetIdentityTutorial.Filters;
using DotnetIdentityTutorial.Services.Implementations;
using DotnetIdentityTutorial.Services.Interfaces;

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

app.UseAuthorization();

app.MapControllers();

app.Run();
