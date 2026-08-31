namespace DotnetIdentityTutorial.Dtos.Auth;

/// <summary>
/// The body of <c>POST /api/v1/Auth/ResetPassword</c> - consumes the stateless token
/// <c>ForgotPasswordAsync</c> generated. For a user who has lost access and can't provide a
/// current password, distinct from <see cref="ChangePasswordRequest"/>.
/// </summary>
public sealed record ResetPasswordRequest(string Email, string Token, string NewPassword);
