namespace DotnetIdentityTutorial.Dtos.Auth;

/// <summary>
/// The body of <c>POST /api/v1/Auth/Confirm2fa</c>'s response - the one-time set of recovery
/// codes generated the moment 2FA is activated. Each can be redeemed exactly once via
/// <c>UserManager.RedeemTwoFactorRecoveryCodeAsync</c> in place of a TOTP code, as a fallback if
/// the user loses their authenticator device. These are shown once and never retrievable again
/// after this response - Identity itself only stores their hashes.
/// </summary>
public sealed record Confirm2faResponse(IReadOnlyList<string> RecoveryCodes);
