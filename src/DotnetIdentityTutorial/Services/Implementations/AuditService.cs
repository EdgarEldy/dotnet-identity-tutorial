using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using DotnetIdentityTutorial.Data;
using DotnetIdentityTutorial.Dtos.AuditLog;
using DotnetIdentityTutorial.Exceptions;
using DotnetIdentityTutorial.Models;
using DotnetIdentityTutorial.Services.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;

namespace DotnetIdentityTutorial.Services.Implementations;

/// <summary>
/// The one place allowed to touch <see cref="AuditLog"/>/<c>AuditLogs</c> directly. Persists a
/// single row per <see cref="LogAsync"/> call (a fast insert, no read-then-write) and answers the
/// paginated read side backing <c>GET /api/v1/AuditLogs</c>.
///
/// The actor is resolved from <see cref="IHttpContextAccessor"/> rather than accepted as a
/// parameter, the same <c>sub</c>/<see cref="ClaimTypes.NameIdentifier"/> claim
/// <c>AuthController.GetCurrentUserId</c> reads, but never throws if it can't be resolved: an
/// audit-logging concern must never be the reason a real mutation fails, and there is currently
/// no call site that reaches <see cref="LogAsync"/> outside a request, but the interface itself
/// has to stay usable if one appears later (background/system code with no ambient
/// <see cref="HttpContext"/>). That is exactly why <see cref="AuditLog.ActorUserId"/> is a
/// nullable column rather than a required one.
/// </summary>
public sealed class AuditService : IAuditService
{
    private const int MaxPageSize = 100;

    private readonly AppDbContext _dbContext;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<AuditService> _logger;

    public AuditService(
        AppDbContext dbContext,
        IHttpContextAccessor httpContextAccessor,
        TimeProvider timeProvider,
        ILogger<AuditService> logger)
    {
        _dbContext = dbContext;
        _httpContextAccessor = httpContextAccessor;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    public async Task LogAsync(string action, string entityType, string entityId, object? details, CancellationToken cancellationToken = default)
    {
        var auditLog = new AuditLog
        {
            ActorUserId = GetActorUserId(),
            Action = action,
            EntityType = entityType,
            EntityId = entityId,
            Details = details is null ? null : JsonSerializer.Serialize(details),
            CreatedAt = _timeProvider.GetUtcNow(),
        };

        _dbContext.AuditLogs.Add(auditLog);

        try
        {
            await _dbContext.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex)
        {
            // The real mutation this call is recording (RbacService/UserAdminService's own
            // SaveChangesAsync or UserManager call) has already committed by the time LogAsync
            // runs - this class's own remarks state an audit-logging concern must never be the
            // reason a real mutation fails, so a failure to persist the audit row itself is
            // logged and swallowed rather than propagated as a 500 for an operation that
            // genuinely succeeded.
            _logger.LogError(ex, "Failed to persist audit log entry for {Action} on {EntityType} {EntityId}", action, entityType, entityId);

            // AuditService shares its AppDbContext with whichever RbacService/UserAdminService
            // call site is calling it (same DI scope), so a failed AuditLog left in the change
            // tracker would otherwise be retried on that context's next unrelated
            // SaveChangesAsync call within the same request.
            _dbContext.Entry(auditLog).State = EntityState.Detached;
        }
    }

    public async Task<(IReadOnlyList<AuditLogResponse> Logs, int TotalCount)> GetAuditLogsAsync(
        int page,
        int pageSize,
        int? actorUserId,
        string? entityType,
        CancellationToken cancellationToken = default)
    {
        if (page < 1)
        {
            throw new BusinessRuleException("page must be 1 or greater.");
        }

        if (pageSize is < 1 or > MaxPageSize)
        {
            throw new BusinessRuleException($"pageSize must be between 1 and {MaxPageSize}.");
        }

        // (page - 1) * pageSize is computed in long arithmetic and range-checked before ever
        // being cast back to the int Skip requires - page has no upper bound of its own, so a
        // large enough value would otherwise overflow Int32 and wrap into an unexpected (often
        // negative) offset, something the database itself may reject with an unhandled exception
        // rather than the documented BusinessRuleException every other bad-pagination-input case
        // above already produces.
        var skip = (long)(page - 1) * pageSize;
        if (skip > int.MaxValue)
        {
            throw new BusinessRuleException("page is too large for the given pageSize.");
        }

        IQueryable<AuditLog> query = _dbContext.AuditLogs;

        if (actorUserId is not null)
        {
            query = query.Where(a => a.ActorUserId == actorUserId);
        }

        if (!string.IsNullOrWhiteSpace(entityType))
        {
            query = query.Where(a => a.EntityType == entityType);
        }

        var totalCount = await query.CountAsync(cancellationToken);

        // Newest-first: the natural default for an audit trail, where the most recent change is
        // almost always what a reader is looking for.
        var logs = await query
            .OrderByDescending(a => a.CreatedAt)
            .Skip((int)skip)
            .Take(pageSize)
            .Select(a => new AuditLogResponse(a.Id, a.ActorUserId, a.Action, a.EntityType, a.EntityId, a.Details, a.CreatedAt))
            .ToListAsync(cancellationToken);

        return (logs, totalCount);
    }

    private int? GetActorUserId()
    {
        var user = _httpContextAccessor.HttpContext?.User;
        var subject = user?.FindFirstValue(JwtRegisteredClaimNames.Sub) ?? user?.FindFirstValue(ClaimTypes.NameIdentifier);

        return subject is not null && int.TryParse(subject, out var userId) ? userId : null;
    }
}
