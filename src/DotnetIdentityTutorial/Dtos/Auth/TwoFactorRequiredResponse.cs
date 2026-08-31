namespace DotnetIdentityTutorial.Dtos.Auth;

/// <summary>
/// The 202 Accepted body <c>AuthController.Login</c> returns when the account has 2FA enabled
/// instead of a <see cref="TokenResponse"/> - the caller isn't done logging in yet, it must
/// present <see cref="TwoFactorToken"/> together with a TOTP/recovery code to
/// <c>POST /api/v1/Auth/VerifyTwoFactor</c> to actually receive a usable token pair.
/// </summary>
public sealed record TwoFactorRequiredResponse(string TwoFactorToken);
