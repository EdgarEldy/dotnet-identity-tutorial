using System.Security.Cryptography;
using System.Text;
using DotnetIdentityTutorial.Data;
using DotnetIdentityTutorial.Exceptions;
using DotnetIdentityTutorial.Identity;
using DotnetIdentityTutorial.Services.Implementations;
using DotnetIdentityTutorial.Services.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Testcontainers.PostgreSql;
using RefreshTokenEntity = DotnetIdentityTutorial.Models.RefreshToken;

namespace DotnetIdentityTutorial.Tests.Services;

/// <summary>
/// Exercises <see cref="ITokenService"/> directly against a real Testcontainers-provisioned
/// PostgreSQL instance - no login/register endpoint exists yet (that's feature/auth-flows), so
/// there is no way to reach token issuance over HTTP on this branch; the service is resolved
/// from DI and called directly, the same pattern as <c>RbacServiceTests</c>/
/// <c>UserAdminServiceTests</c>. Uses <see cref="FakeTimeProvider"/> (shared across the class,
/// like the container) so the SecurityStamp-rejection test can prove it isn't actually an
/// expiry-related rejection by advancing the clock a small amount, well within the refresh
/// token's real lifetime.
/// </summary>
public class TokenServiceTests : IClassFixture<TokenServiceFixture>
{
    private readonly TokenServiceFixture _fixture;

    public TokenServiceTests(TokenServiceFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task IssueThenRefreshTwice_RotatesWithinTheSameFamilyAndChainsReplacedByTokenId()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var tokenService = scope.ServiceProvider.GetRequiredService<ITokenService>();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await CreateUserAsync(userManager);

        var first = await tokenService.IssueTokensAsync(user);
        var second = await tokenService.RefreshAsync(first.RefreshToken);
        var third = await tokenService.RefreshAsync(second.RefreshToken);

        Assert.NotEqual(first.RefreshToken, second.RefreshToken);
        Assert.NotEqual(second.RefreshToken, third.RefreshToken);
        Assert.NotEqual(first.AccessToken, second.AccessToken);

        var firstEntity = await GetByRawTokenAsync(dbContext, first.RefreshToken);
        var secondEntity = await GetByRawTokenAsync(dbContext, second.RefreshToken);
        var thirdEntity = await GetByRawTokenAsync(dbContext, third.RefreshToken);

        // The whole chain stays in the same family - rotation, not a fresh login.
        Assert.Equal(firstEntity.FamilyId, secondEntity.FamilyId);
        Assert.Equal(secondEntity.FamilyId, thirdEntity.FamilyId);

        Assert.NotNull(firstEntity.RevokedAt);
        Assert.Equal(secondEntity.Id, firstEntity.ReplacedByTokenId);

        Assert.NotNull(secondEntity.RevokedAt);
        Assert.Equal(thirdEntity.Id, secondEntity.ReplacedByTokenId);

        Assert.Null(thirdEntity.RevokedAt);
        Assert.Null(thirdEntity.ReplacedByTokenId);
    }

    [Fact]
    public async Task RefreshAsync_TokenAlreadyRotatedAway_ThrowsAndRevokesEveryTokenInTheFamily()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var tokenService = scope.ServiceProvider.GetRequiredService<ITokenService>();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await CreateUserAsync(userManager);

        var first = await tokenService.IssueTokensAsync(user);
        var second = await tokenService.RefreshAsync(first.RefreshToken);

        // Present the first token again - it was already rotated away by the refresh above.
        await Assert.ThrowsAsync<BusinessRuleException>(() => tokenService.RefreshAsync(first.RefreshToken));

        var firstEntity = await GetByRawTokenAsync(dbContext, first.RefreshToken);
        var secondEntity = await GetByRawTokenAsync(dbContext, second.RefreshToken);

        // Reuse detection: every token in the family is now revoked, including the "current"
        // one (second) that had not itself been reused - a stolen token forces a real re-login
        // for the whole session chain, not just rejection of the replayed token.
        Assert.NotNull(firstEntity.RevokedAt);
        Assert.NotNull(secondEntity.RevokedAt);
    }

    [Fact]
    public async Task RefreshAsync_AfterSecurityStampChanges_ThrowsAndRevokesFamilyEvenBeforeNaturalExpiry()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var tokenService = scope.ServiceProvider.GetRequiredService<ITokenService>();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await CreateUserAsync(userManager);

        var issued = await tokenService.IssueTokensAsync(user);

        // Simulate a password change: rotates the user's SecurityStamp. Advance the fake clock
        // by a small amount only - well within the refresh token's real 7-day lifetime - so a
        // failure here can only be explained by the SecurityStamp mismatch, not expiry.
        await userManager.UpdateSecurityStampAsync(user);
        _fixture.TimeProvider.Advance(TimeSpan.FromMinutes(5));

        await Assert.ThrowsAsync<BusinessRuleException>(() => tokenService.RefreshAsync(issued.RefreshToken));

        var entity = await GetByRawTokenAsync(dbContext, issued.RefreshToken);
        Assert.NotNull(entity.RevokedAt);
    }

    [Fact]
    public async Task RefreshAsync_UnknownToken_ThrowsResourceNotFoundException()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var tokenService = scope.ServiceProvider.GetRequiredService<ITokenService>();

        await Assert.ThrowsAsync<ResourceNotFoundException>(() => tokenService.RefreshAsync("not-a-real-token"));
    }

    [Fact]
    public async Task RevokeAsync_BlacklistsJtiAndRevokesEveryActiveRefreshTokenForTheUser()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var tokenService = scope.ServiceProvider.GetRequiredService<ITokenService>();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await CreateUserAsync(userManager);
        var issued = await tokenService.IssueTokensAsync(user);
        var jti = Guid.NewGuid().ToString();

        await tokenService.RevokeAsync(jti, user.Id);

        var isBlacklisted = await dbContext.BlacklistedAccessTokens.AnyAsync(b => b.Jti == jti);
        Assert.True(isBlacklisted);

        var refreshEntity = await GetByRawTokenAsync(dbContext, issued.RefreshToken);
        Assert.NotNull(refreshEntity.RevokedAt);

        // Idempotent: calling it again for the same jti must not throw.
        var exception = await Record.ExceptionAsync(() => tokenService.RevokeAsync(jti, user.Id));
        Assert.Null(exception);
    }

    private static async Task<RefreshTokenEntity> GetByRawTokenAsync(AppDbContext dbContext, string rawToken)
    {
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawToken)));
        return await dbContext.RefreshTokens.SingleAsync(rt => rt.TokenHash == hash);
    }

    private static async Task<ApplicationUser> CreateUserAsync(UserManager<ApplicationUser> userManager)
    {
        var email = $"{Guid.NewGuid():N}@example.com";
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
/// Shared Testcontainers PostgreSQL instance, DI container, and <see cref="FakeTimeProvider"/>
/// for <see cref="TokenServiceTests"/>. Registers the same
/// <c>AddClaimsPrincipalFactory&lt;ApplicationUserClaimsPrincipalFactory&gt;()</c> wiring
/// Program.cs does, plus an in-memory Jwt configuration section matching
/// appsettings.Development.json's shape, so <c>TokenService</c> resolves through DI exactly the
/// way a real request would.
/// </summary>
public sealed class TokenServiceFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer _postgresContainer = new PostgreSqlBuilder("postgres:16")
        .WithDatabase("dotnet_identity_tutorial_token_test")
        .WithUsername("test")
        .WithPassword("test")
        .Build();

    public FakeTimeProvider TimeProvider { get; } = new(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));

    public ServiceProvider ServiceProvider { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        await _postgresContainer.StartAsync();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<TimeProvider>(TimeProvider);

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Issuer"] = "DotnetIdentityTutorial.Tests",
                ["Jwt:Audience"] = "DotnetIdentityTutorial.Tests",
                ["Jwt:SigningKey"] = "test_only_signing_key_at_least_32_bytes_long_for_hmac_sha256",
                ["Jwt:AccessTokenMinutes"] = "15",
                ["Jwt:RefreshTokenDays"] = "7",
            })
            .Build();
        services.AddSingleton<IConfiguration>(configuration);

        services.AddDbContext<AppDbContext>(options =>
            options.UseNpgsql(_postgresContainer.GetConnectionString()));

        services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
            {
                options.Password.RequireDigit = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequiredLength = 8;
            })
            .AddEntityFrameworkStores<AppDbContext>()
            .AddDefaultTokenProviders()
            .AddClaimsPrincipalFactory<ApplicationUserClaimsPrincipalFactory>();

        services.AddScoped<ITokenService, TokenService>();

        ServiceProvider = services.BuildServiceProvider();

        using var scope = ServiceProvider.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await dbContext.Database.MigrateAsync();
    }

    public async Task DisposeAsync()
    {
        await ServiceProvider.DisposeAsync();
        await _postgresContainer.DisposeAsync();
    }
}
