using System.Security.Claims;
using DotnetIdentityTutorial.Data;
using DotnetIdentityTutorial.Exceptions;
using DotnetIdentityTutorial.Identity;
using DotnetIdentityTutorial.Services;
using DotnetIdentityTutorial.Services.Implementations;
using DotnetIdentityTutorial.Services.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Testcontainers.PostgreSql;

namespace DotnetIdentityTutorial.Tests.Services;

/// <summary>
/// Exercises <see cref="ExternalLoginService"/> directly against a real Testcontainers
/// PostgreSQL instance, the same pattern as <c>AuthServiceTests</c>/<c>TokenServiceTests</c>. A
/// real browser OAuth round trip with Google cannot be driven here (this project only has
/// placeholder <c>Authentication:Google:ClientId</c>/<c>ClientSecret</c> configuration values,
/// and <c>ExternalLoginController.Google</c> issues a genuine redirect to Google's own servers),
/// so every scenario below builds an <see cref="ExternalLoginInfo"/> by hand - a
/// <see cref="ClaimsPrincipal"/> carrying the claims Google's own callback would have supplied
/// (<see cref="ClaimTypes.Email"/>/<see cref="ClaimTypes.GivenName"/>/<see cref="ClaimTypes.Surname"/>)
/// under a <see cref="ClaimsIdentity"/> with an authentication type - and calls
/// <see cref="IExternalLoginService.HandleExternalLoginCallbackAsync"/> directly, exactly the
/// pattern ASP.NET Core's own official samples use to test external-login flows. This proves the
/// account-resolution logic itself (new account vs. linking an existing one vs. a returning
/// linked user) without needing live Google credentials or an HTTP redirect.
/// </summary>
public sealed class ExternalLoginServiceTests : IClassFixture<ExternalLoginServiceFixture>
{
    private const string GoogleProvider = "Google";

    private readonly ExternalLoginServiceFixture _fixture;

    public ExternalLoginServiceTests(ExternalLoginServiceFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task HandleExternalLoginCallbackAsync_NoExistingAccount_CreatesALinkedUserInTheUserRole()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var externalLoginService = scope.ServiceProvider.GetRequiredService<IExternalLoginService>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        var email = $"{Guid.NewGuid():N}@example.com";
        var providerKey = Guid.NewGuid().ToString("N");
        var info = BuildExternalLoginInfo(email, providerKey, "Ada", "Lovelace");

        var tokens = await externalLoginService.HandleExternalLoginCallbackAsync(info);

        Assert.False(string.IsNullOrWhiteSpace(tokens.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(tokens.RefreshToken));

        var user = await userManager.FindByEmailAsync(email)
            ?? throw new InvalidOperationException("Test setup failed: no user was created for the new external login.");
        Assert.True(user.EmailConfirmed);
        Assert.Equal("Ada", user.FirstName);
        Assert.Equal("Lovelace", user.LastName);

        var roles = await userManager.GetRolesAsync(user);
        Assert.Contains("USER", roles);

        var logins = await userManager.GetLoginsAsync(user);
        Assert.Contains(logins, l => l.LoginProvider == GoogleProvider && l.ProviderKey == providerKey);
    }

    [Fact]
    public async Task HandleExternalLoginCallbackAsync_ReturningLinkedUser_ResolvesToTheSameExistingAccount()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var externalLoginService = scope.ServiceProvider.GetRequiredService<IExternalLoginService>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        var email = $"{Guid.NewGuid():N}@example.com";
        var providerKey = Guid.NewGuid().ToString("N");
        var firstInfo = BuildExternalLoginInfo(email, providerKey, "Grace", "Hopper");
        await externalLoginService.HandleExternalLoginCallbackAsync(firstInfo);

        var firstSignInUser = await userManager.FindByEmailAsync(email)
            ?? throw new InvalidOperationException("Test setup failed: no user was created on the first sign-in.");

        // A second callback with the same LoginProvider/ProviderKey pair (a fresh ClaimsPrincipal,
        // the way a second real OAuth round trip would hand back a new set of claims each time)
        // must resolve through UserManager.FindByLoginAsync's fast path rather than creating (or
        // attempting to create, and failing on the now-duplicate email) a second account.
        var secondInfo = BuildExternalLoginInfo(email, providerKey, "Grace", "Hopper");
        var tokens = await externalLoginService.HandleExternalLoginCallbackAsync(secondInfo);

        Assert.False(string.IsNullOrWhiteSpace(tokens.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(tokens.RefreshToken));

        var allUsersWithThisEmail = await userManager.Users
            .Where(u => u.Email == email)
            .ToListAsync();
        var returningUser = Assert.Single(allUsersWithThisEmail);
        Assert.Equal(firstSignInUser.Id, returningUser.Id);
    }

    [Fact]
    public async Task HandleExternalLoginCallbackAsync_ExistingPasswordRegisteredUser_LinksTheExternalLoginToTheSameAccount()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var externalLoginService = scope.ServiceProvider.GetRequiredService<IExternalLoginService>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        var email = $"{Guid.NewGuid():N}@example.com";
        var passwordUser = new ApplicationUser
        {
            UserName = email,
            Email = email,
            FirstName = "Existing",
            LastName = "User",
            EmailConfirmed = true,
        };
        var createResult = await userManager.CreateAsync(passwordUser, "Passw0rd1");
        if (!createResult.Succeeded)
        {
            throw new InvalidOperationException(
                $"Test setup failed to create the password-registered user: {string.Join(", ", createResult.Errors.Select(e => e.Description))}");
        }

        var providerKey = Guid.NewGuid().ToString("N");
        var info = BuildExternalLoginInfo(email, providerKey, "Existing", "User");

        var tokens = await externalLoginService.HandleExternalLoginCallbackAsync(info);

        Assert.False(string.IsNullOrWhiteSpace(tokens.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(tokens.RefreshToken));

        var allUsersWithThisEmail = await userManager.Users
            .Where(u => u.Email == email)
            .ToListAsync();
        var singleAccount = Assert.Single(allUsersWithThisEmail);
        Assert.Equal(passwordUser.Id, singleAccount.Id);

        var logins = await userManager.GetLoginsAsync(passwordUser);
        Assert.Contains(logins, l => l.LoginProvider == GoogleProvider && l.ProviderKey == providerKey);
    }

    [Fact]
    public async Task HandleExternalLoginCallbackAsync_NoEmailClaim_ThrowsBusinessRuleException()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var externalLoginService = scope.ServiceProvider.GetRequiredService<IExternalLoginService>();

        var identity = new ClaimsIdentity(GoogleProvider);
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString("N")));
        var principal = new ClaimsPrincipal(identity);
        var info = new ExternalLoginInfo(principal, GoogleProvider, Guid.NewGuid().ToString("N"), GoogleProvider);

        await Assert.ThrowsAsync<BusinessRuleException>(
            () => externalLoginService.HandleExternalLoginCallbackAsync(info));
    }

    private static ExternalLoginInfo BuildExternalLoginInfo(string email, string providerKey, string givenName, string surname)
    {
        var identity = new ClaimsIdentity(GoogleProvider);
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, providerKey));
        identity.AddClaim(new Claim(ClaimTypes.Email, email));
        identity.AddClaim(new Claim(ClaimTypes.GivenName, givenName));
        identity.AddClaim(new Claim(ClaimTypes.Surname, surname));
        var principal = new ClaimsPrincipal(identity);

        return new ExternalLoginInfo(principal, GoogleProvider, providerKey, GoogleProvider);
    }
}

/// <summary>
/// Shared Testcontainers PostgreSQL instance and DI container for
/// <see cref="ExternalLoginServiceTests"/>, matching <c>AuthServiceFixture</c>'s own construction
/// as closely as possible: <see cref="ExternalLoginService"/> has the same kind of dependencies
/// (<c>UserManager</c>, <c>SignInManager</c>, <c>ITokenService</c>, <c>IAuditService</c>) as
/// <c>AuthService</c>, and the default <c>USER</c> role a brand-new external-login account gets
/// assigned has to exist beforehand the same way.
/// </summary>
public sealed class ExternalLoginServiceFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer _postgresContainer = new PostgreSqlBuilder("postgres:16")
        .WithDatabase("dotnet_identity_tutorial_external_login_test")
        .WithUsername("test")
        .WithPassword("test")
        .Build();

    public ServiceProvider ServiceProvider { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        await _postgresContainer.StartAsync();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero)));

        // AuditService resolves an actor from IHttpContextAccessor - there is no real HTTP
        // request in this service-layer test, so it resolves to a null actor, the same expected
        // behavior AuthServiceFixture documents for its own tests.
        services.AddHttpContextAccessor();

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Issuer"] = "DotnetIdentityTutorial.Tests",
                ["Jwt:Audience"] = "DotnetIdentityTutorial.Tests",
                ["Jwt:SigningKey"] = "test_only_signing_key_at_least_32_bytes_long_for_hmac_sha256",
                ["Jwt:AccessTokenMinutes"] = "15",
                ["Jwt:RefreshTokenDays"] = "7",
                ["App:BaseUrl"] = "http://localhost:5277",
            })
            .Build();
        services.AddSingleton<IConfiguration>(configuration);
        services.Configure<JwtSettings>(configuration.GetSection(JwtSettings.SectionName));

        services.AddDbContext<AppDbContext>(options =>
            options.UseNpgsql(_postgresContainer.GetConnectionString()));

        services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
            {
                options.Password.RequireDigit = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequiredLength = 8;

                options.SignIn.RequireConfirmedAccount = true;
            })
            .AddEntityFrameworkStores<AppDbContext>()
            .AddDefaultTokenProviders()
            .AddClaimsPrincipalFactory<ApplicationUserClaimsPrincipalFactory>();

        services.AddScoped<ITokenService, TokenService>();
        services.AddScoped<IAuditService, AuditService>();
        services.AddScoped<IExternalLoginService, ExternalLoginService>();

        ServiceProvider = services.BuildServiceProvider();

        using var scope = ServiceProvider.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await dbContext.Database.MigrateAsync();

        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
        if (!await roleManager.RoleExistsAsync("USER"))
        {
            await roleManager.CreateAsync(new ApplicationRole { Name = "USER" });
        }
    }

    public async Task DisposeAsync()
    {
        await ServiceProvider.DisposeAsync();
        await _postgresContainer.DisposeAsync();
    }
}
