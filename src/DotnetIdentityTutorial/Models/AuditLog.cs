namespace DotnetIdentityTutorial.Models;

/// <summary>
/// A single audit trail entry, recorded by <c>Services/Implementations/AuditService</c> for
/// every RBAC or account-security mutation (role/permission creation, role-permission
/// assignment/removal, user role assignment/removal, user lock/unlock). Read back via
/// <c>GET /api/v1/AuditLogs</c>.
///
/// <see cref="ActorUserId"/> is nullable rather than required: <c>IAuditService.LogAsync</c>'s
/// own signature carries no caller-supplied actor, so <c>AuditService</c> resolves it from the
/// current request's <c>ClaimsPrincipal</c> via <c>IHttpContextAccessor</c> - a mutation with no
/// authenticated principal in scope (there is no such call site today, but the interface itself
/// must stay usable if one appears later) still gets its row recorded, with a null actor, rather
/// than failing the whole mutation over an audit-logging concern. The same reasoning is why the
/// foreign key to <see cref="Identity.ApplicationUser"/> below uses <c>SetNull</c> rather than
/// <c>Cascade</c> on delete: the audit trail is meant to outlive the account that produced it,
/// unlike <see cref="RefreshToken"/>'s own user-owned rows.
///
/// <see cref="Details"/> holds whatever object <c>LogAsync</c>'s own <c>details</c> parameter
/// received, serialized with <c>System.Text.Json</c> and stored as a native Postgres
/// <c>jsonb</c> column (see <see cref="Configurations.AuditLogConfiguration"/>) rather than a
/// bespoke key/value table - the shape of "details" genuinely differs per action (a permission
/// id here, a lockout timestamp there), and jsonb keeps that flexible without forcing every
/// caller through a fixed schema.
///
/// <see cref="CreatedAt"/> is written via the injected <see cref="TimeProvider"/> from
/// <c>AuditService</c>, never <c>DateTime.UtcNow</c>, matching every other timestamp in this
/// project. Fluent API configuration lives in <see cref="Configurations.AuditLogConfiguration"/>,
/// not data annotations here.
/// </summary>
public class AuditLog
{
    public int Id { get; set; }

    public int? ActorUserId { get; set; }

    public required string Action { get; set; }

    public required string EntityType { get; set; }

    public required string EntityId { get; set; }

    public string? Details { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
}
