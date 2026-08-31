namespace DotnetIdentityTutorial.Models;

/// <summary>
/// Marks a single access token (by its <c>jti</c> claim) as revoked before its own natural
/// expiry - the one piece of otherwise-stateless JWT validation that still needs a database
/// round trip, checked by the JWT Bearer handler's <c>OnTokenValidated</c> event in
/// <c>Program.cs</c> on every authenticated request, so an explicit logout
/// (<c>TokenService.RevokeAsync</c>) takes effect immediately instead of waiting up to
/// <c>Jwt:AccessTokenMinutes</c> for the token to expire on its own.
///
/// <see cref="ExpiresAt"/> mirrors what the access token's own expiry already was, purely so
/// <c>BackgroundServices/ExpiredTokenCleanupService</c> knows when this row is safe to delete -
/// a blacklist entry adds nothing once the token it targets would have expired naturally
/// anyway. Both timestamps are written via the injected <see cref="TimeProvider"/>, never
/// <c>DateTime.UtcNow</c>. Fluent API configuration lives in
/// <see cref="Configurations.BlacklistedAccessTokenConfiguration"/>, not data annotations here.
/// </summary>
public class BlacklistedAccessToken
{
    public int Id { get; set; }

    public int UserId { get; set; }

    public required string Jti { get; set; }

    public DateTimeOffset BlacklistedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }
}
