using DotnetIdentityTutorial.Dtos.Auth;
using DotnetIdentityTutorial.Dtos.User;

namespace DotnetIdentityTutorial.Services.Interfaces;

/// <summary>
/// The one place allowed to call <c>UserManager&lt;ApplicationUser&gt;</c>/
/// <c>SignInManager&lt;ApplicationUser&gt;</c> for the account lifecycle: registration, email
/// confirmation, login, forgot/reset password, change password, logout, and the current-user
/// profile. Token issuance/refresh/revocation itself is delegated to <see cref="ITokenService"/>,
/// this service never builds/signs a JWT or touches <c>RefreshToken</c>/
/// <c>BlacklistedAccessToken</c> directly.
/// </summary>
public interface IAuthService
{
    /// <summary>
    /// Creates the account, assigns the seeded <c>USER</c> role, and sends a confirmation email
    /// (a link carrying a stateless <c>UserManager</c>-generated token) via
    /// <see cref="IEmailService"/>. Does not issue tokens - with
    /// <c>options.SignIn.RequireConfirmedAccount = true</c>, a freshly-registered account can't
    /// sign in until <see cref="ConfirmEmailAsync"/> succeeds. Throws
    /// <see cref="Exceptions.BusinessRuleException"/> if account creation itself fails (a
    /// duplicate email, a password rejected by Identity's own validators, ...).
    /// </summary>
    Task RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Consumes the token from the confirmation link. Throws
    /// <see cref="Exceptions.ResourceNotFoundException"/> if <paramref name="userId"/> doesn't
    /// exist, <see cref="Exceptions.BusinessRuleException"/> if the token is invalid or expired.
    /// </summary>
    Task ConfirmEmailAsync(int userId, string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates credentials via <c>SignInManager.CheckPasswordSignInAsync</c> (which correctly
    /// integrates with Identity's own lockout counting and reflects
    /// <c>RequireConfirmedAccount</c> through <c>SignInResult.IsNotAllowed</c>) and, on success,
    /// issues a fresh token pair via <see cref="ITokenService"/>. Throws
    /// <see cref="Exceptions.BusinessRuleException"/> for a locked-out, not-allowed
    /// (unconfirmed), or otherwise failed sign-in.
    /// </summary>
    Task<TokenResponse> LoginAsync(LoginRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Thin delegation to <c>ITokenService.RefreshAsync</c>.
    /// </summary>
    Task<TokenResponse> RefreshAsync(RefreshRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Always does the same amount of work and returns the same way regardless of whether
    /// <paramref name="request"/>'s email matches an account - see this method's own
    /// implementation remarks for why an early return here would make the endpoint a
    /// user-enumeration oracle.
    /// </summary>
    Task ForgotPasswordAsync(ForgotPasswordRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Consumes the token <see cref="ForgotPasswordAsync"/> generated and sets a new password.
    /// Identity itself rotates the user's <c>SecurityStamp</c> on a successful reset, which is
    /// what invalidates every outstanding refresh token family (see
    /// <c>TokenService.RefreshAsync</c>'s own <c>SecurityStamp</c> comparison) - nothing extra is
    /// needed here for that to hold.
    /// </summary>
    Task ResetPasswordAsync(ResetPasswordRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// For an authenticated user who knows their current password - distinct from
    /// <see cref="ResetPasswordAsync"/>. Same automatic <c>SecurityStamp</c> rotation applies.
    /// </summary>
    Task ChangePasswordAsync(int userId, ChangePasswordRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Thin delegation to <c>ITokenService.RevokeAsync</c>.
    /// </summary>
    Task LogoutAsync(int userId, string accessTokenJti, DateTimeOffset accessTokenExpiresAt, CancellationToken cancellationToken = default);

    /// <summary>
    /// Loads the caller's own profile and roles. <see cref="CurrentUserResponse.Permissions"/> is
    /// returned empty here - the controller fills it in from the caller's own JWT "permission"
    /// claims, this service has no need to re-query them from the database.
    /// </summary>
    Task<CurrentUserResponse> GetMeAsync(int userId, CancellationToken cancellationToken = default);
}
