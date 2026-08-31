namespace DotnetIdentityTutorial.Dtos.AuditLog;

/// <summary>
/// The shape returned by <c>GET /api/v1/AuditLogs</c>. <c>Details</c> is the raw JSON text
/// stored in the <c>jsonb</c> column, passed through as-is rather than re-typed into a DTO
/// property per action - see <c>Models.AuditLog</c>'s own remarks for why its shape varies.
/// </summary>
public record AuditLogResponse(
    int Id,
    int? ActorUserId,
    string Action,
    string EntityType,
    string EntityId,
    string? Details,
    DateTimeOffset CreatedAt);
