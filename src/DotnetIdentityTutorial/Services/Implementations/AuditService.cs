using DotnetIdentityTutorial.Services.Interfaces;

namespace DotnetIdentityTutorial.Services.Implementations;

/// <summary>
/// Stub implementation for feature/rbac: logs the audit entry rather than persisting it to a
/// dedicated table, since <c>AuditLog</c>/<c>audit_logs</c> don't exist until
/// feature/audit-logging. Every RBAC mutation call site (<see cref="IAuditService"/>'s
/// consumers) is already wired against the real interface, so swapping this implementation out
/// for one backed by <c>AppDbContext</c> later requires no change anywhere else.
/// </summary>
public sealed class AuditService : IAuditService
{
    private readonly ILogger<AuditService> _logger;

    public AuditService(ILogger<AuditService> logger)
    {
        _logger = logger;
    }

    public Task LogAsync(string action, string entityType, string entityId, object? details)
    {
        _logger.LogInformation(
            "RBAC audit: {Action} on {EntityType} {EntityId}: {Details}",
            action,
            entityType,
            entityId,
            details);

        return Task.CompletedTask;
    }
}
