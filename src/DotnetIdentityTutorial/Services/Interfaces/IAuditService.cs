using DotnetIdentityTutorial.Dtos.AuditLog;

namespace DotnetIdentityTutorial.Services.Interfaces;

/// <summary>
/// Records and reads back the audit trail for RBAC and account-security changes (role/permission
/// mutations, role/permission assignments, user lock/unlock, and later password/credential
/// events too).
///
/// <see cref="LogAsync"/>'s own signature carries no caller-supplied actor - every RBAC mutation
/// call site (<c>RbacService</c>, <c>UserAdminService</c>) calls it exactly the same way whether
/// or not a request is in flight, so <c>AuditService</c> resolves "who did this" itself from the
/// ambient <c>HttpContext</c> rather than requiring every call site to pass it through.
/// </summary>
public interface IAuditService
{
    Task LogAsync(string action, string entityType, string entityId, object? details);

    /// <summary>
    /// A paginated, newest-first read of the audit trail, optionally filtered by the actor who
    /// performed the action and/or the type of entity it was performed on. Backs
    /// <c>GET /api/v1/AuditLogs</c>.
    /// </summary>
    Task<(IReadOnlyList<AuditLogResponse> Logs, int TotalCount)> GetAuditLogsAsync(
        int page,
        int pageSize,
        int? actorUserId,
        string? entityType,
        CancellationToken cancellationToken = default);
}
