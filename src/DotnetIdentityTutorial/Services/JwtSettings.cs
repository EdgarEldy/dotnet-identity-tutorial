namespace DotnetIdentityTutorial.Services;

/// <summary>
/// Strongly-typed binding of the <c>Jwt</c> configuration section, bound once and shared by
/// both <c>Program.cs</c> (building <c>TokenValidationParameters</c> for the JWT Bearer scheme)
/// and <c>Services/Implementations/TokenService</c> (issuing tokens). Before this existed, both
/// read the same five config keys independently as raw strings, a typo in either copy would
/// have silently desynced token issuance from token validation.
/// </summary>
public sealed class JwtSettings
{
    public const string SectionName = "Jwt";

    public required string Issuer { get; set; }

    public required string Audience { get; set; }

    public required string SigningKey { get; set; }

    public int AccessTokenMinutes { get; set; }

    public int RefreshTokenDays { get; set; }
}
