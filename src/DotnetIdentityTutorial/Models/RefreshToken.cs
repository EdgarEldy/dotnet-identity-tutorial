namespace DotnetIdentityTutorial.Models;

/// <summary>
/// A single opaque, server-side refresh token, stored hashed - the raw value handed to the
/// client at issuance is never persisted anywhere, only its <see cref="TokenHash"/>. Rotation
/// with reuse detection is built on three fields together: <see cref="FamilyId"/> ties every
/// token descended from the same original login into one chain, <see cref="RevokedAt"/> marks
/// a token as already spent (presenting a revoked token again is reuse, see
/// <c>Services/Implementations/TokenService</c>), and <see cref="ReplacedByTokenId"/> points at
/// the token a given row was rotated into, so the chain can be walked either direction.
///
/// <see cref="SecurityStampAtIssuance"/> captures <c>ApplicationUser.SecurityStamp</c> at the
/// moment this token was issued; <c>TokenService.RefreshAsync</c> compares it against the
/// user's *current* stamp on every refresh, a mismatch (password change, or any other Identity
/// event that rotates the stamp) revokes the whole family regardless of expiry - see the
/// README's "Access tokens and refresh tokens" design section.
///
/// Every timestamp here is written via the injected <see cref="TimeProvider"/> from
/// <c>TokenService</c>, never <c>DateTime.UtcNow</c>, so tests can control elapsed time with
/// <c>FakeTimeProvider</c> instead of real delays. Fluent API configuration lives in
/// <see cref="Configurations.RefreshTokenConfiguration"/>, not data annotations here.
/// </summary>
public class RefreshToken
{
    public int Id { get; set; }

    public int UserId { get; set; }

    public required string TokenHash { get; set; }

    public Guid FamilyId { get; set; }

    public required string SecurityStampAtIssuance { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }

    public int? ReplacedByTokenId { get; set; }
}
