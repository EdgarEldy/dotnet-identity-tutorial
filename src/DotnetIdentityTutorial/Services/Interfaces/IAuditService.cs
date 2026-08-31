namespace DotnetIdentityTutorial.Services.Interfaces;

/// <summary>
/// Records an entry in the audit trail for an RBAC or account-security change (role/permission
/// mutations, role/permission assignments, user lock/unlock, and later - once
/// feature/audit-logging lands - password/credential events too).
///
/// This branch (feature/rbac) only stubs the implementation: the real <c>audit_logs</c> table
/// and <c>AuditLog</c> entity don't exist yet, they're feature/audit-logging's job. Every RBAC
/// mutation call site still calls this interface now, exactly as it will once the real
/// implementation lands, so no call site needs to be revisited later - only
/// <see cref="DotnetIdentityTutorial.Services.Implementations.AuditService"/>'s internals
/// change.
/// </summary>
public interface IAuditService
{
    Task LogAsync(string action, string entityType, string entityId, object? details);
}
