using System.Security.Cryptography;
using System.Text;
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
using Microsoft.Extensions.Options;
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

        await tokenService.RevokeAsync(jti, user.Id, issued.AccessTokenExpiresAt);

        var isBlacklisted = await dbContext.BlacklistedAccessTokens.AnyAsync(b => b.Jti == jti);
        Assert.True(isBlacklisted);

        var refreshEntity = await GetByRawTokenAsync(dbContext, issued.RefreshToken);
        Assert.NotNull(refreshEntity.RevokedAt);

        // Idempotent: calling it again for the same jti must not throw.
        var exception = await Record.ExceptionAsync(() => tokenService.RevokeAsync(jti, user.Id, issued.AccessTokenExpiresAt));
        Assert.Null(exception);
    }

    [Fact]
    public async Task IsAccessTokenBlacklistedAsync_ReflectsRevocation()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var tokenService = scope.ServiceProvider.GetRequiredService<ITokenService>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await CreateUserAsync(userManager);
        var issued = await tokenService.IssueTokensAsync(user);
        var jti = Guid.NewGuid().ToString();

        Assert.False(await tokenService.IsAccessTokenBlacklistedAsync(jti));

        await tokenService.RevokeAsync(jti, user.Id, issued.AccessTokenExpiresAt);

        Assert.True(await tokenService.IsAccessTokenBlacklistedAsync(jti));
    }

    [Fact]
    public async Task RefreshAsync_ReusedAndExpiredToken_StillRevokesFamily()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var tokenService = scope.ServiceProvider.GetRequiredService<ITokenService>();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await CreateUserAsync(userManager);

        var first = await tokenService.IssueTokensAsync(user);
        var second = await tokenService.RefreshAsync(first.RefreshToken);

        // Advance well past the refresh token's own lifetime so the reused first token is now
        // both revoked (rotated away by the refresh above) and expired.
        _fixture.TimeProvider.Advance(TimeSpan.FromDays(30));

        await Assert.ThrowsAsync<BusinessRuleException>(() => tokenService.RefreshAsync(first.RefreshToken));

        // Reuse detection must still have fired despite the token also being expired: the
        // still-active descendant (second) is revoked too, not just silently ignored.
        var secondEntity = await GetByRawTokenAsync(dbContext, second.RefreshToken);
        Assert.NotNull(secondEntity.RevokedAt);
    }

    /// <summary>
    /// Deliberately does NOT use <c>_fixture.TimeProvider</c> (the shared clock every test above
    /// uses) to sign the token under test here. <c>ValidateTwoFactorChallengeTokenAsync</c> hands
    /// the token to <c>JwtSecurityTokenHandler.ValidateToken</c> with no custom lifetime seam, so
    /// its <c>nbf</c>/<c>exp</c> claims are checked against the real system clock - the exact same
    /// "not reachable through this seam at all" limitation <c>AuthWebApplicationFactory</c>'s own
    /// remarks document for JWT Bearer's lifetime validation in <c>Program.cs</c>. The shared
    /// fixture's clock is anchored to a fixed, arbitrary past date (2026-01-01) for the sake of
    /// the refresh-token tests above, which only ever compare against database columns written and
    /// read through that same injected clock - never through a third-party library's own
    /// real-clock check. Signing a token with that same far-in-the-past clock and then handing it
    /// to real-clock JWT validation would make it look already expired regardless of the scenario
    /// under test, which is exactly what happened the first time this test was written against the
    /// shared fixture directly. A fresh <see cref="FakeTimeProvider"/> seeded from real
    /// <see cref="DateTimeOffset.UtcNow"/> keeps the token's own claims aligned with the clock
    /// <c>ValidateToken</c> actually checks against, matching how <c>TokenService</c> is seeded
    /// with <c>TimeProvider.System</c> in production.
    /// </summary>
    [Fact]
    public async Task IssueTwoFactorChallengeTokenAsync_ThenValidate_ReturnsTheSameUserId()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await CreateUserAsync(userManager);
        var tokenService = CreateTokenServiceWithClock(scope, new FakeTimeProvider(DateTimeOffset.UtcNow));

        var challengeToken = await tokenService.IssueTwoFactorChallengeTokenAsync(user);
        var userId = await tokenService.ValidateTwoFactorChallengeTokenAsync(challengeToken);

        Assert.Equal(user.Id, userId);
    }

    /// <summary>
    /// Proves expiry without a real 5-minute wait and without relying on
    /// <see cref="FakeTimeProvider.Advance"/> after issuance - advancing a fake clock has no
    /// effect on the real system clock <c>ValidateToken</c> actually checks against (see this
    /// class's own remarks on <see cref="IssueTwoFactorChallengeTokenAsync_ThenValidate_ReturnsTheSameUserId"/>
    /// for why). Instead this signs the token with a clock already 11 minutes in the past relative
    /// to real time - so the token's own <c>exp</c> claim (baseline + the 5-minute
    /// <c>TwoFactorChallengeMinutes</c> lifetime) is already 6 minutes behind real "now" the
    /// moment it's minted, deterministically, the same "move the persisted expiry into the past
    /// directly" technique <c>AuthAccountLockoutE2ETests</c> uses for Identity's own un-seamed
    /// lockout clock. 11 minutes, not 6: <c>TokenValidationParameters</c>'s own default
    /// <c>ClockSkew</c> is 5 minutes, so an <c>exp</c> only 1 minute behind "now" (the first
    /// version of this test) still validates as not-yet-expired - the back-dating has to clear
    /// that tolerance too, not just the token's own 5-minute lifetime.
    /// </summary>
    [Fact]
    public async Task ValidateTwoFactorChallengeTokenAsync_AfterItsFiveMinuteWindowHasPassed_ThrowsBusinessRuleException()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await CreateUserAsync(userManager);
        var tokenService = CreateTokenServiceWithClock(scope, new FakeTimeProvider(DateTimeOffset.UtcNow.AddMinutes(-11)));

        var challengeToken = await tokenService.IssueTwoFactorChallengeTokenAsync(user);

        await Assert.ThrowsAsync<BusinessRuleException>(() => tokenService.ValidateTwoFactorChallengeTokenAsync(challengeToken));
    }

    /// <summary>
    /// Proves the audience-based isolation described in <c>ITokenService.IssueTwoFactorChallengeTokenAsync</c>'s
    /// own remarks actually holds, not just conceptually: a real access token (signed with the
    /// same key, but the configured <c>Jwt:Audience</c> rather than
    /// <c>TokenService.TwoFactorChallengeAudience</c>) must be rejected by
    /// <see cref="ITokenService.ValidateTwoFactorChallengeTokenAsync"/> the same way an ordinary
    /// bearer token is rejected by <c>ValidateTwoFactorChallengeTokenAsync</c>'s own audience
    /// check - proving a leaked/replayed access token can never be used to complete a 2FA
    /// challenge it was never issued for. Uses the same real-time-anchored clock as the round-trip
    /// test above, for the same reason - this must fail on its audience check specifically, not
    /// incidentally look expired because of the shared fixture's unrelated past baseline.
    /// </summary>
    [Fact]
    public async Task ValidateTwoFactorChallengeTokenAsync_GivenAnOrdinaryAccessToken_ThrowsBusinessRuleException()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await CreateUserAsync(userManager);
        var tokenService = CreateTokenServiceWithClock(scope, new FakeTimeProvider(DateTimeOffset.UtcNow));

        var issued = await tokenService.IssueTokensAsync(user);

        await Assert.ThrowsAsync<BusinessRuleException>(() => tokenService.ValidateTwoFactorChallengeTokenAsync(issued.AccessToken));
    }

    /// <summary>
    /// Proves the challenge token is bound to the user's <c>SecurityStamp</c> at issuance, the
    /// same staleness protection <see cref="RefreshToken"/> already applies via
    /// <see cref="RefreshToken.SecurityStampAtIssuance"/>. Without this, a password reset landing
    /// in the gap between <c>Login</c> returning a challenge and <c>VerifyTwoFactor</c> consuming
    /// it would go unnoticed - this test rotates the stamp directly via
    /// <c>UserManager.UpdateSecurityStampAsync</c> (the same primitive Identity itself calls
    /// internally on a real password change) rather than actually changing the password, since
    /// the point under test is the stamp comparison itself, not password-change plumbing already
    /// covered by <c>AuthServiceTests.ChangePasswordAsync_RevokesEveryOutstandingRefreshTokenFamily</c>.
    /// </summary>
    [Fact]
    public async Task ValidateTwoFactorChallengeTokenAsync_AfterSecurityStampRotates_ThrowsBusinessRuleException()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await CreateUserAsync(userManager);
        var tokenService = CreateTokenServiceWithClock(scope, new FakeTimeProvider(DateTimeOffset.UtcNow));

        var challengeToken = await tokenService.IssueTwoFactorChallengeTokenAsync(user);
        await userManager.UpdateSecurityStampAsync(user);

        await Assert.ThrowsAsync<BusinessRuleException>(() => tokenService.ValidateTwoFactorChallengeTokenAsync(challengeToken));
    }

    /// <summary>
    /// Builds a <see cref="TokenService"/> directly (not resolved from <paramref name="scope"/>'s
    /// own DI container) so a test can supply its own <see cref="TimeProvider"/> instead of the
    /// fixture-wide <see cref="TokenServiceFixture.TimeProvider"/> singleton every other test in
    /// this class shares - see the two-factor challenge token tests above for why that distinction
    /// matters here specifically. Every other dependency still comes from the fixture's real
    /// Testcontainers-backed DI container, only the clock is swapped.
    /// </summary>
    private static ITokenService CreateTokenServiceWithClock(IServiceScope scope, TimeProvider timeProvider)
    {
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var claimsPrincipalFactory = scope.ServiceProvider.GetRequiredService<IUserClaimsPrincipalFactory<ApplicationUser>>();
        var jwtOptions = scope.ServiceProvider.GetRequiredService<IOptions<JwtSettings>>();
        var identityOptions = scope.ServiceProvider.GetRequiredService<IOptions<IdentityOptions>>();

        return new TokenService(dbContext, userManager, claimsPrincipalFactory, timeProvider, jwtOptions, identityOptions);
    }

    private static async Task<RefreshTokenEntity> GetByRawTokenAsync(AppDbContext dbContext, string rawToken)
    {
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawToken)));

        // AsNoTracking, and always re-queried: TokenService revokes rows via ExecuteUpdateAsync,
        // which bypasses the change tracker entirely. Without this, a call here that follows an
        // earlier tracked read of the same row (same AppDbContext instance, shared with
        // TokenService within one DI scope) would return the stale, already-tracked in-memory
        // value instead of what ExecuteUpdateAsync actually wrote to the database.
        return await dbContext.RefreshTokens
            .AsNoTracking()
            .SingleAsync(rt => rt.TokenHash == hash);
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
