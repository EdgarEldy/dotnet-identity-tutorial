using DotnetIdentityTutorial.Data;
using DotnetIdentityTutorial.Dtos.Auth;
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
/// A handful of sanity checks for <see cref="AuthService"/> against a real Testcontainers
/// PostgreSQL instance, the same pattern as <c>TokenServiceTests</c> - no HTTP layer exists yet
/// for this branch beyond <c>AuthController</c> itself, and full end-to-end coverage (rate
/// limiting, lockout with <c>FakeTimeProvider</c>, the whole register -&gt; confirm -&gt; login
/// -&gt; refresh -&gt; logout lifecycle) is a separate pass. This class exists to prove the
/// register/confirm/login gate and the SecurityStamp-driven refresh-token invalidation on
/// password change actually hold, not to be the project's full auth-flows test suite.
/// </summary>
public sealed class AuthServiceTests : IClassFixture<AuthServiceFixture>
{
    private readonly AuthServiceFixture _fixture;

    public AuthServiceTests(AuthServiceFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task RegisterThenLogin_BeforeConfirmation_IsRejectedAsNotAllowed()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var authService = scope.ServiceProvider.GetRequiredService<IAuthService>();
        var email = $"{Guid.NewGuid():N}@example.com";

        await authService.RegisterAsync(new RegisterRequest(email, "Passw0rd1", "Ada", "Lovelace"));

        // RequireConfirmedAccount = true means CheckPasswordSignInAsync's own IsNotAllowed
        // branch fires here, not a successful sign-in, even with the exact right password.
        await Assert.ThrowsAsync<BusinessRuleException>(
            () => authService.LoginAsync(new LoginRequest(email, "Passw0rd1")));
    }

    [Fact]
    public async Task RegisterThenConfirmThenLogin_IssuesTokensAndAssignsTheDefaultRole()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var authService = scope.ServiceProvider.GetRequiredService<IAuthService>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var email = $"{Guid.NewGuid():N}@example.com";

        await authService.RegisterAsync(new RegisterRequest(email, "Passw0rd1", "Grace", "Hopper"));

        var user = await userManager.FindByEmailAsync(email)
            ?? throw new InvalidOperationException("Test setup failed: registered user was not found.");
        var roles = await userManager.GetRolesAsync(user);
        Assert.Contains("USER", roles);

        var confirmationToken = await userManager.GenerateEmailConfirmationTokenAsync(user);
        await authService.ConfirmEmailAsync(user.Id, confirmationToken);

        var loginResult = await authService.LoginAsync(new LoginRequest(email, "Passw0rd1"));
        Assert.False(loginResult.RequiresTwoFactor);
        Assert.NotNull(loginResult.Tokens);
        Assert.False(string.IsNullOrWhiteSpace(loginResult.Tokens!.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(loginResult.Tokens!.RefreshToken));
    }

    [Fact]
    public async Task ForgotPasswordAsync_DoesNotThrowForAnUnknownOrAKnownEmail()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var authService = scope.ServiceProvider.GetRequiredService<IAuthService>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var email = $"{Guid.NewGuid():N}@example.com";
        await CreateConfirmedUserAsync(userManager, email);

        // Neither branch (a real account vs. a made-up email) should ever surface a different
        // outcome to the caller - both must simply complete without throwing.
        var knownEmailException = await Record.ExceptionAsync(
            () => authService.ForgotPasswordAsync(new ForgotPasswordRequest(email)));
        var unknownEmailException = await Record.ExceptionAsync(
            () => authService.ForgotPasswordAsync(new ForgotPasswordRequest($"{Guid.NewGuid():N}@example.com")));

        Assert.Null(knownEmailException);
        Assert.Null(unknownEmailException);
    }

    [Fact]
    public async Task ChangePasswordAsync_RevokesEveryOutstandingRefreshTokenFamily()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var authService = scope.ServiceProvider.GetRequiredService<IAuthService>();
        var tokenService = scope.ServiceProvider.GetRequiredService<ITokenService>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var email = $"{Guid.NewGuid():N}@example.com";
        var user = await CreateConfirmedUserAsync(userManager, email);

        var issued = await tokenService.IssueTokensAsync(user);

        await authService.ChangePasswordAsync(user.Id, new ChangePasswordRequest("Passw0rd1", "NewPassw0rd2"));

        // ChangePasswordAsync rotates the SecurityStamp via Identity's own UserManager
        // internals - the refresh token issued before the change now fails its SecurityStamp
        // comparison in TokenService.RefreshAsync, regardless of its own expiry, exactly the
        // invariant the README's "SecurityStamp and refresh token revocation" section requires.
        await Assert.ThrowsAsync<BusinessRuleException>(() => tokenService.RefreshAsync(issued.RefreshToken));
    }

    private static async Task<ApplicationUser> CreateConfirmedUserAsync(UserManager<ApplicationUser> userManager, string email)
    {
        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            FirstName = "Test",
            LastName = "User",
            EmailConfirmed = true,
        };

        var result = await userManager.CreateAsync(user, "Passw0rd1");
        if (!result.Succeeded)
        {
            throw new InvalidOperationException(
                $"Failed to create test user: {string.Join(", ", result.Errors.Select(e => e.Description))}");
        }

        return user;
    }
}

/// <summary>
/// Shared Testcontainers PostgreSQL instance and DI container for <see cref="AuthServiceTests"/>,
/// the same construction as <c>TokenServiceFixture</c> plus the <c>USER</c> role
/// <see cref="AuthService.RegisterAsync"/> assigns to every self-registered account (seeded here
/// directly via <c>RoleManager</c>, the same sanctioned bootstrap exception <c>DbInitializer</c>
/// itself relies on, rather than pulling in the whole of <c>DbInitializer</c> for one role).
/// </summary>
public sealed class AuthServiceFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer _postgresContainer = new PostgreSqlBuilder("postgres:16")
        .WithDatabase("dotnet_identity_tutorial_auth_test")
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

        // AuditService (now a real, AppDbContext-backed implementation as of
        // feature/audit-logging) needs IHttpContextAccessor to resolve an actor - there is no
        // real HTTP request in this service-layer test, so it resolves to a null actor, which is
        // the expected, documented behavior for a call with no ambient HttpContext.
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
        services.AddScoped<IEmailService, EmailService>();
        services.AddScoped<IAuditService, AuditService>();
        services.AddScoped<IAuthService, AuthService>();

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
