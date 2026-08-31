using System.IdentityModel.Tokens.Jwt;
using System.Linq.Expressions;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using DotnetIdentityTutorial.Data;
using DotnetIdentityTutorial.Dtos.Auth;
using DotnetIdentityTutorial.Exceptions;
using DotnetIdentityTutorial.Identity;
using DotnetIdentityTutorial.Models;
using DotnetIdentityTutorial.Services.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace DotnetIdentityTutorial.Services.Implementations;

/// <summary>
/// The one place allowed to build/sign a JWT and touch <see cref="RefreshToken"/>/
/// <see cref="BlacklistedAccessToken"/> directly. Every timestamp recorded here (issuance,
/// expiry, revocation, blacklisting) is read from the injected <see cref="TimeProvider"/>, never
/// <c>DateTime.UtcNow</c>, so tests can advance a <c>FakeTimeProvider</c> instead of waiting on
/// real token lifetimes.
///
/// Rotation with reuse detection: <see cref="RefreshAsync"/> atomically claims the token just
/// presented (an <c>ExecuteUpdateAsync</c> conditioned on it still being unrevoked, closing the
/// race where two concurrent requests both read the same unrevoked token and would otherwise
/// both rotate it) and issues a new one in the same <see cref="RefreshToken.FamilyId"/>.
/// Presenting an already-revoked token again (reuse, or the losing side of that race), or one
/// whose captured <see cref="RefreshToken.SecurityStampAtIssuance"/> no longer matches the
/// user's current <c>SecurityStamp</c> (a password change), revokes every other unrevoked token
/// in the family, not just the one just used - a single compromised or stale token invalidates
/// the whole session chain, per the README's "Access tokens and refresh tokens" design section.
/// The revoked-token check runs before the expiry check specifically so a stolen token replayed
/// after its own natural expiry still triggers family revocation as defense in depth.
///
/// <see cref="IssueTwoFactorChallengeTokenAsync"/>/<see cref="ValidateTwoFactorChallengeTokenAsync"/>
/// add a third, narrower kind of token: a "two-factor challenge token" (the README's own "partial
/// login ticket"), issued by <c>AuthService.LoginAsync</c> instead of a real access/refresh pair
/// when the account has 2FA enabled. It is a JWT signed with the same key as a real access token
/// but a different <c>aud</c> claim (<see cref="TwoFactorChallengeAudience"/> instead of
/// <see cref="JwtSettings.Audience"/>) - that mismatch alone is what makes it fail the JWT Bearer
/// scheme's own audience validation in <c>Program.cs</c> if ever presented as a Bearer token,
/// with zero changes needed to that pipeline. It is validated purely by signature/issuer/audience/
/// lifetime, the same as a normal access token's signature check, and is never persisted (no
/// database row, nothing to blacklist) since it grants no access to a protected resource by
/// itself.
///
/// Neither the raw access token nor the raw refresh token is ever logged or put in an exception
/// message here - only their hashes (<see cref="RefreshToken.TokenHash"/>) or unique ids
/// (the access token's <c>jti</c>) ever reach the database or a log line. The raw
/// <c>SecurityStamp</c> claim <c>ApplicationUserClaimsPrincipalFactory</c>'s base implementation
/// adds (for Identity's own cookie-validation purposes) is stripped before signing, an access
/// token is not encrypted the way an Identity cookie ticket is, so that value would otherwise
/// leak in plain, trivially-decodable form to anyone holding the JWT.
/// </summary>
public sealed class TokenService : ITokenService
{
    /// <summary>
    /// Deliberately much shorter than the 15-minute access token: a two-factor challenge token
    /// only needs to survive the brief gap between Login returning "2FA required" and the caller
    /// submitting a code to VerifyTwoFactor, not an entire session. A narrow window also limits
    /// how long a leaked challenge token (still just a password-verified-but-not-yet-2FA-verified
    /// ticket, not a bearer token, but still worth minimizing) remains usable.
    /// </summary>
    private const int TwoFactorChallengeMinutes = 5;

    /// <summary>
    /// The audience a two-factor challenge token is signed with - deliberately different from
    /// <see cref="JwtSettings.Audience"/>, the actual security boundary described in this class's
    /// own <see cref="IssueTwoFactorChallengeTokenAsync"/> remarks.
    /// </summary>
    private const string TwoFactorChallengeAudience = "DotnetIdentityTutorial.TwoFactorChallenge";

    private readonly AppDbContext _dbContext;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IUserClaimsPrincipalFactory<ApplicationUser> _claimsPrincipalFactory;
    private readonly TimeProvider _timeProvider;
    private readonly JwtSettings _jwtSettings;
    private readonly string _securityStampClaimType;
    private readonly SigningCredentials _signingCredentials;

    public TokenService(
        AppDbContext dbContext,
        UserManager<ApplicationUser> userManager,
        IUserClaimsPrincipalFactory<ApplicationUser> claimsPrincipalFactory,
        TimeProvider timeProvider,
        IOptions<JwtSettings> jwtOptions,
        IOptions<IdentityOptions> identityOptions)
    {
        _dbContext = dbContext;
        _userManager = userManager;
        _claimsPrincipalFactory = claimsPrincipalFactory;
        _timeProvider = timeProvider;
        _jwtSettings = jwtOptions.Value;
        _securityStampClaimType = identityOptions.Value.ClaimsIdentity.SecurityStampClaimType;

        // Built once here rather than per token issuance - the signing key never changes at
        // runtime, so there is no reason to re-derive it from configuration on every call.
        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SigningKey));
        _signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
    }

    public async Task<TokenResponse> IssueTokensAsync(ApplicationUser user, CancellationToken cancellationToken = default)
    {
        var now = _timeProvider.GetUtcNow();
        var (response, _) = await IssueTokensInternalAsync(user, Guid.NewGuid(), now, cancellationToken);
        return response;
    }

    public async Task<TokenResponse> RefreshAsync(string rawRefreshToken, CancellationToken cancellationToken = default)
    {
        var tokenHash = HashToken(rawRefreshToken);
        var now = _timeProvider.GetUtcNow();

        var existingToken = await _dbContext.RefreshTokens
            .AsNoTracking()
            .FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash, cancellationToken);

        if (existingToken is null)
        {
            throw new ResourceNotFoundException("Refresh token was not found.");
        }

        if (existingToken.RevokedAt is not null)
        {
            // Reuse detection takes priority over the token's own expiry: a stolen token
            // replayed after it (and its whole family) would naturally have expired is still
            // evidence of compromise, checking expiry first would let that case skip revocation.
            await RevokeTokensAsync(rt => rt.FamilyId == existingToken.FamilyId, now, cancellationToken);
            throw new BusinessRuleException(
                "This refresh token has already been used. The entire session family has been revoked; sign in again.");
        }

        if (existingToken.ExpiresAt <= now)
        {
            throw new ResourceNotFoundException("Refresh token has expired.");
        }

        var user = await _userManager.FindByIdAsync(existingToken.UserId.ToString())
            ?? throw new ResourceNotFoundException("The user this refresh token belongs to no longer exists.");

        // Both sides normalized the same way (a user's SecurityStamp can be null before Identity
        // first assigns one): comparing the stored value against a raw, possibly-null current
        // value would treat "still null" as a mismatch and force-revoke a family that never
        // actually had its credentials changed.
        var currentSecurityStamp = user.SecurityStamp ?? string.Empty;
        if (!string.Equals(existingToken.SecurityStampAtIssuance, currentSecurityStamp, StringComparison.Ordinal))
        {
            // The SecurityStamp captured at issuance no longer matches the user's current one -
            // a password change (or any other Identity event that rotates the stamp) happened
            // since this token was handed out. Reject regardless of the token's own expiry and
            // revoke the whole family, not just this token: a password change invalidates every
            // outstanding session.
            await RevokeTokensAsync(rt => rt.FamilyId == existingToken.FamilyId, now, cancellationToken);
            throw new BusinessRuleException(
                "This refresh token is no longer valid because the account's credentials changed. Sign in again.");
        }

        // Atomically claim this token for rotation: the update only affects a row if it is still
        // unrevoked at this exact moment, so if a concurrent request already claimed it between
        // our read above and this statement, claimedCount is 0 here instead of both requests
        // successfully rotating the same token into two independent children.
        var claimedCount = await _dbContext.RefreshTokens
            .Where(rt => rt.Id == existingToken.Id && rt.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(rt => rt.RevokedAt, now), cancellationToken);

        if (claimedCount == 0)
        {
            await RevokeTokensAsync(rt => rt.FamilyId == existingToken.FamilyId, now, cancellationToken);
            throw new BusinessRuleException(
                "This refresh token is being used concurrently. The entire session family has been revoked; sign in again.");
        }

        var (response, newEntity) = await IssueTokensInternalAsync(user, existingToken.FamilyId, now, cancellationToken);

        await _dbContext.RefreshTokens
            .Where(rt => rt.Id == existingToken.Id)
            .ExecuteUpdateAsync(s => s.SetProperty(rt => rt.ReplacedByTokenId, newEntity.Id), cancellationToken);

        return response;
    }

    public async Task RevokeAsync(string accessTokenJti, int userId, DateTimeOffset accessTokenExpiresAt, CancellationToken cancellationToken = default)
    {
        var now = _timeProvider.GetUtcNow();

        // Idempotent check-then-insert, same pattern as DbInitializer's seeding: logout being
        // called twice for the same access token (a retried request, a double-click) must not
        // fail, and the unique index on Jti is the schema-level backstop against a race.
        var alreadyBlacklisted = await _dbContext.BlacklistedAccessTokens
            .AnyAsync(b => b.Jti == accessTokenJti, cancellationToken);

        if (!alreadyBlacklisted)
        {
            _dbContext.BlacklistedAccessTokens.Add(new BlacklistedAccessToken
            {
                UserId = userId,
                Jti = accessTokenJti,
                BlacklistedAt = now,
                // The caller's own real expiry, not recomputed from current Jwt:AccessTokenMinutes
                // configuration - if that setting is ever changed between issuance and logout, a
                // recomputed value could tell ExpiredTokenCleanupService to delete this row before
                // the actual JWT (signed with the expiry that was real at issuance) stops being
                // cryptographically valid, reviving a token that was supposed to stay revoked.
                ExpiresAt = accessTokenExpiresAt,
            });
            await _dbContext.SaveChangesAsync(cancellationToken);
        }

        // RevokeAsync's signature only carries the access token's jti and the user id, not
        // which refresh token family issued that particular access token (the JWT itself never
        // carries a family claim) - there is no reliable way from here to single out "the
        // current session" versus any other one the user has open. Revoking every active family
        // for the user is the simpler, still-correct choice: "logout" ends every outstanding
        // session rather than leaving other devices/tabs holding refresh tokens whose access
        // token was never blacklisted but that a caller might reasonably expect to be dead too.
        await RevokeTokensAsync(rt => rt.UserId == userId, now, cancellationToken);
    }

    public Task<bool> IsAccessTokenBlacklistedAsync(string jti, CancellationToken cancellationToken = default)
    {
        return _dbContext.BlacklistedAccessTokens.AnyAsync(b => b.Jti == jti, cancellationToken);
    }

    public Task<string> IssueTwoFactorChallengeTokenAsync(ApplicationUser user, CancellationToken cancellationToken = default)
    {
        var now = _timeProvider.GetUtcNow();

        // Only a subject and a fresh jti - unlike a real access token, this carries none of the
        // caller's role/permission claims. It grants nothing on its own beyond the right to
        // attempt VerifyTwoFactor within its own short expiry, so there is nothing else worth
        // putting in it, and less to leak if it ever ends up somewhere it shouldn't.
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

        var jwt = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: TwoFactorChallengeAudience,
            claims: claims,
            notBefore: now.UtcDateTime,
            expires: now.AddMinutes(TwoFactorChallengeMinutes).UtcDateTime,
            signingCredentials: _signingCredentials);

        return Task.FromResult(new JwtSecurityTokenHandler().WriteToken(jwt));
    }

    public Task<int> ValidateTwoFactorChallengeTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = _jwtSettings.Issuer,
            ValidateAudience = true,
            ValidAudience = TwoFactorChallengeAudience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = _signingCredentials.Key,
            ValidateLifetime = true,
        };

        ClaimsPrincipal principal;
        try
        {
            // MapInboundClaims = false: JwtSecurityTokenHandler's own default (true, kept for
            // backward compatibility) silently rewrites short claim types like "sub" into long
            // legacy URIs (ClaimTypes.NameIdentifier) on the ClaimsPrincipal it hands back -
            // exactly the "sub" claim IssueTwoFactorChallengeTokenAsync put in the token in the
            // first place. Left at its default, the read below would never find it under
            // JwtRegisteredClaimNames.Sub. ASP.NET Core's own JwtBearerHandler (see Program.cs)
            // doesn't hit this - it validates through the newer JsonWebTokenHandler, which
            // defaults to no remapping - but this method builds its own JwtSecurityTokenHandler
            // directly, so the same behavior has to be requested explicitly here.
            var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
            principal = handler.ValidateToken(token, validationParameters, out _);
        }
        catch (Exception)
        {
            // Never logs or echoes the raw token value - same "a raw token value never appears
            // in a log line or an error message" rule applied to refresh tokens elsewhere in
            // this class, extended here even though this token isn't the refresh token itself.
            throw new BusinessRuleException("The two-factor challenge token is invalid or has expired.");
        }

        var subject = principal.FindFirstValue(JwtRegisteredClaimNames.Sub);
        if (subject is null || !int.TryParse(subject, out var userId))
        {
            throw new BusinessRuleException("The two-factor challenge token is invalid or has expired.");
        }

        return Task.FromResult(userId);
    }

    private async Task<(TokenResponse Response, RefreshToken Entity)> IssueTokensInternalAsync(
        ApplicationUser user, Guid familyId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var accessTokenExpiresAt = now.AddMinutes(_jwtSettings.AccessTokenMinutes);

        var principal = await _claimsPrincipalFactory.CreateAsync(user);

        // Drops the raw SecurityStamp claim UserClaimsPrincipalFactory's base implementation
        // adds for Identity's own cookie-validation purposes - see this class's own remarks for
        // why that value must not leave the server inside an unencrypted bearer token.
        var claims = principal.Claims
            .Where(c => c.Type != _securityStampClaimType)
            .ToList();
        claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));

        var jwt = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.Audience,
            claims: claims,
            notBefore: now.UtcDateTime,
            expires: accessTokenExpiresAt.UtcDateTime,
            signingCredentials: _signingCredentials);

        var accessToken = new JwtSecurityTokenHandler().WriteToken(jwt);

        var rawRefreshToken = GenerateRawRefreshToken();
        var refreshTokenExpiresAt = now.AddDays(_jwtSettings.RefreshTokenDays);

        var refreshTokenEntity = new RefreshToken
        {
            UserId = user.Id,
            TokenHash = HashToken(rawRefreshToken),
            FamilyId = familyId,
            // Captured at this exact moment, not read again later - RefreshAsync compares this
            // stored value against the user's SecurityStamp *at refresh time*.
            SecurityStampAtIssuance = user.SecurityStamp ?? string.Empty,
            CreatedAt = now,
            ExpiresAt = refreshTokenExpiresAt,
        };

        _dbContext.RefreshTokens.Add(refreshTokenEntity);
        await _dbContext.SaveChangesAsync(cancellationToken);

        var response = new TokenResponse(accessToken, rawRefreshToken, accessTokenExpiresAt, refreshTokenExpiresAt);
        return (response, refreshTokenEntity);
    }

    /// <summary>
    /// Bulk-revokes every currently-unrevoked <see cref="RefreshToken"/> matching
    /// <paramref name="scope"/> (a family, or every token for a user) via <c>ExecuteUpdateAsync</c>
    /// rather than loading each row into the change tracker just to set one column, the same
    /// bulk-mutate idiom <c>ExpiredTokenCleanupService</c> already uses for deletes.
    /// </summary>
    private async Task RevokeTokensAsync(Expression<Func<RefreshToken, bool>> scope, DateTimeOffset now, CancellationToken cancellationToken)
    {
        await _dbContext.RefreshTokens
            .Where(scope)
            .Where(rt => rt.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(rt => rt.RevokedAt, now), cancellationToken);
    }

    private static string GenerateRawRefreshToken()
    {
        // 32 random bytes (256 bits) of entropy, base64url-encoded so the raw value is safe to
        // put directly in a JSON body or a URL query string without further escaping.
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Base64UrlEncoder.Encode(bytes);
    }

    private static string HashToken(string rawToken)
    {
        // SHA-256 is fine here - unlike a password, a refresh token is already 256 bits of
        // uniformly random entropy, there is no offline dictionary/brute-force concern a slow
        // hash (bcrypt/PBKDF2/Argon2) would defend against.
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
        return Convert.ToHexString(hashBytes);
    }
}
