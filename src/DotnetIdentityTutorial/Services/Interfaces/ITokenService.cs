using DotnetIdentityTutorial.Dtos.Auth;
using DotnetIdentityTutorial.Identity;

namespace DotnetIdentityTutorial.Services.Interfaces;

/// <summary>
/// The one place allowed to build/sign a JWT and touch <c>RefreshToken</c>/
/// <c>BlacklistedAccessToken</c> directly - see <c>Services/Implementations/TokenService</c> for
/// the rotation-with-reuse-detection and <c>SecurityStamp</c>-comparison mechanics described in
/// the README's "Access tokens and refresh tokens" design section.
/// </summary>
public interface ITokenService
{
    /// <summary>
    /// Issues a brand-new access + refresh token pair for <paramref name="user"/>, starting a
    /// new refresh token family.
    /// </summary>
    Task<TokenResponse> IssueTokensAsync(ApplicationUser user, CancellationToken cancellationToken = default);

    /// <summary>
    /// Exchanges a valid, unexpired, unrevoked refresh token for a new pair in the same family.
    /// Throws <c>ResourceNotFoundException</c> if the token doesn't exist or has expired.
    /// Throws <c>BusinessRuleException</c> if the token was already used once (reuse detection -
    /// the whole family is revoked) or if the user's <c>SecurityStamp</c> has changed since this
    /// token was issued (a password change - the whole family is revoked).
    /// </summary>
    Task<TokenResponse> RefreshAsync(string rawRefreshToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Logout: blacklists the access token identified by <paramref name="accessTokenJti"/> so
    /// <c>OnTokenValidated</c> rejects it immediately instead of waiting for its own expiry, and
    /// revokes every currently-active refresh token belonging to <paramref name="userId"/>.
    /// </summary>
    Task RevokeAsync(string accessTokenJti, int userId, CancellationToken cancellationToken = default);
}
