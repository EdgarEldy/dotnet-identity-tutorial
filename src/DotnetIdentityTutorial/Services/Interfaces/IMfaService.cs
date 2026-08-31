using DotnetIdentityTutorial.Dtos.Auth;

namespace DotnetIdentityTutorial.Services.Interfaces;

/// <summary>
/// The one place allowed to call <c>UserManager&lt;ApplicationUser&gt;</c> for the TOTP-based
/// multi-factor authentication lifecycle: generating an authenticator secret, activating 2FA
/// once the first code is verified, and disabling it again. Wraps Identity's own built-in TOTP
/// support (<c>GetAuthenticatorKeyAsync</c>/<c>ResetAuthenticatorKeyAsync</c>,
/// <c>VerifyTwoFactorTokenAsync</c>, <c>SetTwoFactorEnabledAsync</c>,
/// <c>GenerateNewTwoFactorRecoveryCodesAsync</c>) rather than reimplementing TOTP - see the
/// README's "Design decisions around Identity's built-in mechanisms".
///
/// Deliberately does not call <c>IAuditService</c> anywhere: that interface's own remarks defer
/// password/credential-event auditing to feature/audit-logging, not this branch.
/// </summary>
public interface IMfaService
{
    /// <summary>
    /// Generates (or reuses, if a setup is already in progress) an authenticator secret for
    /// <paramref name="userId"/>. Does not enable 2FA - <c>TwoFactorEnabled</c> stays false until
    /// <see cref="Confirm2faAsync"/> verifies the first code generated from this secret. Reusing
    /// an existing, not-yet-confirmed key rather than always resetting it means calling this
    /// endpoint twice in a row (e.g. a page refresh mid-setup) doesn't invalidate a QR code the
    /// user may have already scanned.
    /// </summary>
    Task<Enable2faResponse> Enable2faAsync(int userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies the first code generated from the secret <see cref="Enable2faAsync"/> handed
    /// back, and if valid, activates 2FA and returns a freshly generated set of one-time recovery
    /// codes. Throws <c>BusinessRuleException</c> if the code is invalid.
    /// </summary>
    Task<Confirm2faResponse> Confirm2faAsync(int userId, Confirm2faRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Disables 2FA and resets the authenticator key, so a future re-enable always starts from a
    /// fresh secret rather than silently reusing a possibly-compromised one.
    /// </summary>
    Task Disable2faAsync(int userId, CancellationToken cancellationToken = default);
}
