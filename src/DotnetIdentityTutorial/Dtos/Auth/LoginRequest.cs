namespace DotnetIdentityTutorial.Dtos.Auth;

/// <summary>
/// The body of <c>POST /api/v1/Auth/Login</c>.
/// </summary>
public sealed record LoginRequest(string Email, string Password);
