namespace DotnetIdentityTutorial.Dtos.Auth;

/// <summary>
/// The body of <c>POST /api/v1/Auth/Confirm2fa</c>. <see cref="Code"/> is the first 6-digit TOTP
/// code generated from the secret <c>Enable2fa</c> returned, proving the authenticator app was
/// set up correctly before 2FA is actually activated on the account.
/// </summary>
public sealed record Confirm2faRequest(string Code);
