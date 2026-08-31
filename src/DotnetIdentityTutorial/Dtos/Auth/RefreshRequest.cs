namespace DotnetIdentityTutorial.Dtos.Auth;

/// <summary>
/// The body of <c>POST /api/v1/Auth/Refresh</c>. <see cref="RefreshToken"/> is the raw opaque
/// value handed to the client at issuance - never logged, only ever hashed before it's compared
/// against <c>RefreshToken.TokenHash</c> in <c>TokenService</c>.
/// </summary>
public sealed record RefreshRequest(string RefreshToken);
