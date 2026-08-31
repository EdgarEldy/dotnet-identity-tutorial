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

    public AuditService(AppDbContext dbContext, IHttpContextAccessor httpContextAccessor, TimeProvider timeProvider)
    {
        _dbContext = dbContext;
        _httpContextAccessor = httpContextAccessor;
        _timeProvider = timeProvider;
    }

    public async Task LogAsync(string action, string entityType, string entityId, object? details)
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
        await _dbContext.SaveChangesAsync();
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

        var query = _dbContext.AuditLogs.AsQueryable();

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
            .Skip((page - 1) * pageSize)
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
