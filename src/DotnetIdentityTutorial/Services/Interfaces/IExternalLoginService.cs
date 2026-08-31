using DotnetIdentityTutorial.Dtos.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;

namespace DotnetIdentityTutorial.Services.Interfaces;

/// <summary>
/// The one place allowed to call <c>SignInManager&lt;ApplicationUser&gt;</c>/
/// <c>UserManager&lt;ApplicationUser&gt;</c> for the external-login flow - matches the same
/// contract/implementation pattern <see cref="IAuthService"/> already establishes for the
/// password-based account lifecycle. An external sign-in still goes through the exact same
/// <see cref="ITokenService"/> issuance pipeline as a password login once the account is
/// resolved, no separate token code path.
/// </summary>
public interface IExternalLoginService
{
    /// <summary>
    /// Builds the <see cref="AuthenticationProperties"/> that carry the post-challenge redirect
    /// back to <paramref name="redirectUrl"/> (this API's own callback action) through Google's
    /// OAuth round trip.
    /// </summary>
    AuthenticationProperties BuildChallengeProperties(string redirectUrl);

    /// <summary>
    /// Reads the external-login information Google's callback left on the current request's
    /// ambient external-login temp cookie. Returns <c>null</c> if that information isn't present
    /// (e.g. the callback endpoint was navigated to directly, without a preceding challenge) -
    /// the caller is expected to turn a <c>null</c> result into a
    /// <see cref="Exceptions.BusinessRuleException"/>.
    /// </summary>
    Task<ExternalLoginInfo?> GetExternalLoginInfoAsync();

    /// <summary>
    /// Resolves <paramref name="info"/> to an <c>ApplicationUser</c> - a returning user who
    /// already linked this exact external account, an existing password-registered account
    /// linking Google for the first time, or a brand-new account - and issues a real token pair
    /// via <see cref="ITokenService"/> for it. See the implementation's own remarks for the
    /// account-linking precedence.
    /// </summary>
    Task<TokenResponse> HandleExternalLoginCallbackAsync(ExternalLoginInfo info, CancellationToken cancellationToken = default);
}
