namespace DotnetIdentityTutorial.Dtos.Auth;

/// <summary>
/// The body of <c>POST /api/v1/Auth/Register</c>. Registration only creates the account and
/// sends a confirmation email (see <c>AuthService.RegisterAsync</c>) - it never issues tokens,
/// since <c>RequireConfirmedAccount</c> means the account can't sign in yet.
/// </summary>
public sealed record RegisterRequest(
    string Email,
    string Password,
    string FirstName,
    string LastName);
