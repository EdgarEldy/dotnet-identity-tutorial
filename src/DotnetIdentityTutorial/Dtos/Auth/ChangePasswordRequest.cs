namespace DotnetIdentityTutorial.Dtos.Auth;

/// <summary>
/// The body of <c>POST /api/v1/Auth/ChangePassword</c> - for the currently authenticated user,
/// who proves ownership with their current password rather than a mailed token. Distinct from
/// <see cref="ResetPasswordRequest"/>.
/// </summary>
public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);
