using System.IdentityModel.Tokens.Jwt;
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
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DotnetIdentityTutorial.Services.Implementations;

/// <summary>
/// The one place allowed to build/sign a JWT and touch <see cref="RefreshToken"/>/
/// <see cref="BlacklistedAccessToken"/> directly. Every timestamp recorded here (issuance,
/// expiry, revocation, blacklisting) is read from the injected <see cref="TimeProvider"/>, never
/// <c>DateTime.UtcNow</c>, so tests can advance a <c>FakeTimeProvider</c> instead of waiting on
/// real token lifetimes.
///
/// Rotation with reuse detection: <see cref="RefreshAsync"/> revokes the token just presented and
/// issues a new one in the same <see cref="RefreshToken.FamilyId"/>. Presenting an
/// already-revoked token again (reuse) or one whose captured
/// <see cref="RefreshToken.SecurityStampAtIssuance"/> no longer matches the user's current
/// <c>SecurityStamp</c> (a password change) revokes every other unrevoked token in the family,
/// not just the one just used - a single compromised or stale token invalidates the whole
/// session chain, per the README's "Access tokens and refresh tokens" design section.
///
/// Neither the raw access token nor the raw refresh token is ever logged or put in an exception
/// message here - only their hashes (<see cref="RefreshToken.TokenHash"/>) or unique ids
/// (the access token's <c>jti</c>) ever reach the database or a log line.
/// </summary>
public sealed class TokenService : ITokenService
{
    private readonly AppDbContext _dbContext;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IUserClaimsPrincipalFactory<ApplicationUser> _claimsPrincipalFactory;
    private readonly TimeProvider _timeProvider;
    private readonly IConfiguration _configuration;

    public TokenService(
        AppDbContext dbContext,
        UserManager<ApplicationUser> userManager,
        IUserClaimsPrincipalFactory<ApplicationUser> claimsPrincipalFactory,
        TimeProvider timeProvider,
        IConfiguration configuration)
    {
        _dbContext = dbContext;
        _userManager = userManager;
        _claimsPrincipalFactory = claimsPrincipalFactory;
        _timeProvider = timeProvider;
        _configuration = configuration;
    }

    public async Task<TokenResponse> IssueTokensAsync(ApplicationUser user, CancellationToken cancellationToken = default)
    {
        var (response, _) = await IssueTokensInternalAsync(user, Guid.NewGuid(), cancellationToken);
        return response;
    }

    public async Task<TokenResponse> RefreshAsync(string rawRefreshToken, CancellationToken cancellationToken = default)
    {
        var tokenHash = HashToken(rawRefreshToken);
        var now = _timeProvider.GetUtcNow();

        var existingToken = await _dbContext.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash, cancellationToken);

        if (existingToken is null || existingToken.ExpiresAt <= now)
        {
            throw new ResourceNotFoundException("Refresh token was not found or has expired.");
        }

        if (existingToken.RevokedAt is not null)
        {
            // Reuse detection: this exact token was already rotated away once (or revoked by a
            // prior SecurityStamp mismatch/logout). Presenting it again means it leaked - revoke
            // every other still-active token in the family too, defense in depth even though the
            // normal rotation path below already revokes the token it replaces.
            await RevokeFamilyAsync(existingToken.FamilyId, now, cancellationToken);
            throw new BusinessRuleException(
                "This refresh token has already been used. The entire session family has been revoked; sign in again.");
        }

        var user = await _userManager.FindByIdAsync(existingToken.UserId.ToString())
            ?? throw new ResourceNotFoundException("The user this refresh token belongs to no longer exists.");

        if (!string.Equals(existingToken.SecurityStampAtIssuance, user.SecurityStamp, StringComparison.Ordinal))
        {
            // The SecurityStamp captured at issuance no longer matches the user's current one -
            // a password change (or any other Identity event that rotates the stamp) happened
            // since this token was handed out. Reject regardless of the token's own expiry and
            // revoke the whole family, not just this token: a password change invalidates every
            // outstanding session.
            await RevokeFamilyAsync(existingToken.FamilyId, now, cancellationToken);
            throw new BusinessRuleException(
                "This refresh token is no longer valid because the account's credentials changed. Sign in again.");
        }

        existingToken.RevokedAt = now;

        var (response, newEntity) = await IssueTokensInternalAsync(user, existingToken.FamilyId, cancellationToken);
        existingToken.ReplacedByTokenId = newEntity.Id;

        await _dbContext.SaveChangesAsync(cancellationToken);

        return response;
    }

    public async Task RevokeAsync(string accessTokenJti, int userId, CancellationToken cancellationToken = default)
    {
        var now = _timeProvider.GetUtcNow();

        // Idempotent check-then-insert, same pattern as DbInitializer's seeding: logout being
        // called twice for the same access token (a retried request, a double-click) must not
        // fail, and the unique index on Jti is the schema-level backstop against a race.
        var alreadyBlacklisted = await _dbContext.BlacklistedAccessTokens
            .AnyAsync(b => b.Jti == accessTokenJti, cancellationToken);

        if (!alreadyBlacklisted)
        {
            var accessTokenMinutes = _configuration.GetValue<int>("Jwt:AccessTokenMinutes");
            _dbContext.BlacklistedAccessTokens.Add(new BlacklistedAccessToken
            {
                UserId = userId,
                Jti = accessTokenJti,
                BlacklistedAt = now,
                ExpiresAt = now.AddMinutes(accessTokenMinutes),
            });
        }

        // RevokeAsync's signature only carries the access token's jti and the user id, not
        // which refresh token family issued that particular access token (the JWT itself never
        // carries a family claim) - there is no reliable way from here to single out "the
        // current session" versus any other one the user has open. Revoking every active family
        // for the user is the simpler, still-correct choice: "logout" ends every outstanding
        // session rather than leaving other devices/tabs holding refresh tokens whose access
        // token was never blacklisted but that a caller might reasonably expect to be dead too.
        var activeRefreshTokens = await _dbContext.RefreshTokens
            .Where(rt => rt.UserId == userId && rt.RevokedAt == null)
            .ToListAsync(cancellationToken);

        foreach (var refreshToken in activeRefreshTokens)
        {
            refreshToken.RevokedAt = now;
        }

        await _dbContext.SaveChangesAsync(cancellationToken);
    }

    private async Task<(TokenResponse Response, RefreshToken Entity)> IssueTokensInternalAsync(
        ApplicationUser user, Guid familyId, CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        var accessTokenMinutes = _configuration.GetValue<int>("Jwt:AccessTokenMinutes");
        var refreshTokenDays = _configuration.GetValue<int>("Jwt:RefreshTokenDays");
        var accessTokenExpiresAt = now.AddMinutes(accessTokenMinutes);

        var principal = await _claimsPrincipalFactory.CreateAsync(user);
        var claims = principal.Claims.ToList();
        claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));

        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:SigningKey"]!));
        var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

        var jwt = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            notBefore: now.UtcDateTime,
            expires: accessTokenExpiresAt.UtcDateTime,
            signingCredentials: signingCredentials);

        var accessToken = new JwtSecurityTokenHandler().WriteToken(jwt);

        var rawRefreshToken = GenerateRawRefreshToken();
        var refreshTokenExpiresAt = now.AddDays(refreshTokenDays);

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

    private async Task RevokeFamilyAsync(Guid familyId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var tokens = await _dbContext.RefreshTokens
            .Where(rt => rt.FamilyId == familyId && rt.RevokedAt == null)
            .ToListAsync(cancellationToken);

        foreach (var token in tokens)
        {
            token.RevokedAt = now;
        }

        await _dbContext.SaveChangesAsync(cancellationToken);
    }

    private static string GenerateRawRefreshToken()
    {
        // 32 random bytes (256 bits) of entropy, base64url-encoded so the raw value is safe to
        // put directly in a JSON body or a URL query string without further escaping.
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
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
