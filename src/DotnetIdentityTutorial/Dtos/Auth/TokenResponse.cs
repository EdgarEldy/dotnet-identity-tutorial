namespace DotnetIdentityTutorial.Dtos.Auth;

/// <summary>
/// The raw access token + raw refresh token pair returned by <c>ITokenService</c>. This is the
/// only place either raw value exists outside the client - neither is ever logged, put in an
/// exception message, or persisted unhashed (see <c>Models.RefreshToken.TokenHash</c>).
/// feature/auth-flows returns this same shape directly from <c>AuthController</c>'s
/// login/refresh endpoints, so it lives under Dtos/Auth even though no controller uses it yet
/// on this branch.
/// </summary>
public sealed record TokenResponse(
    string AccessToken,
    string RefreshToken,
    DateTimeOffset AccessTokenExpiresAt,
    DateTimeOffset RefreshTokenExpiresAt);
