namespace DotnetIdentityTutorial.Dtos.Auth;

/// <summary>
/// The body of <c>POST /api/v1/Auth/Enable2fa</c>. <see cref="SharedKey"/> is the raw,
/// unformatted TOTP secret (for manual entry into an authenticator app);
/// <see cref="AuthenticatorUri"/> is the same secret packaged as an <c>otpauth://totp/...</c>
/// URI a frontend can render directly as a QR code. 2FA is not yet active at this point -
/// <c>TwoFactorEnabled</c> only flips to true once <c>Confirm2faAsync</c> verifies the first
/// code generated from this secret.
/// </summary>
public sealed record Enable2faResponse(string SharedKey, string AuthenticatorUri);
