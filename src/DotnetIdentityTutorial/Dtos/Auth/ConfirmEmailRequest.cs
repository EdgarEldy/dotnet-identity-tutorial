namespace DotnetIdentityTutorial.Dtos.Auth;

/// <summary>
/// Binds from the query string on <c>GET /api/v1/Auth/ConfirmEmail?userId={id}&amp;token={token}</c>
/// (the link <c>AuthService.RegisterAsync</c> sends via <c>IEmailService</c>), not a JSON body -
/// a confirmation link has to work from a plain browser navigation.
/// </summary>
public sealed record ConfirmEmailRequest(int UserId, string Token);
