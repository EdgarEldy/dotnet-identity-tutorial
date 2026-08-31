namespace DotnetIdentityTutorial.Dtos.Auth;

/// <summary>
/// The body of <c>POST /api/v1/Auth/ForgotPassword</c>. See <c>AuthService.ForgotPasswordAsync</c>
/// for the anti-enumeration guarantee: the response is identical whether or not this email
/// matches an account.
/// </summary>
public sealed record ForgotPasswordRequest(string Email);
