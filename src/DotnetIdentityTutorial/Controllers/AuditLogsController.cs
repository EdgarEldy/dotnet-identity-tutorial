using DotnetIdentityTutorial.Dtos.AuditLog;
using DotnetIdentityTutorial.Extensions;
using DotnetIdentityTutorial.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DotnetIdentityTutorial.Controllers;

/// <summary>
/// Read-only access to the audit trail <see cref="IAuditService"/> writes to from every RBAC and
/// account-security mutation. Paginated the same way <see cref="UsersController.GetUsers"/> is,
/// with the same <c>X-Total-Count</c>/<c>Link</c> header convention instead of a body wrapper.
/// </summary>
[ApiController]
[Route("api/v1/[controller]")]
public sealed class AuditLogsController : ControllerBase
{
    private const int DefaultPageSize = 20;

    private readonly IAuditService _auditService;

    public AuditLogsController(IAuditService auditService)
    {
        _auditService = auditService;
    }

    [HttpGet]
    [Authorize(Policy = "AUDIT:READ")]
    public async Task<ActionResult<IReadOnlyList<AuditLogResponse>>> GetAuditLogs(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = DefaultPageSize,
        [FromQuery] int? actorUserId = null,
        [FromQuery] string? entityType = null,
        CancellationToken cancellationToken = default)
    {
        var (logs, totalCount) = await _auditService.GetAuditLogsAsync(page, pageSize, actorUserId, entityType, cancellationToken);

        var nextLink = page * pageSize < totalCount
            ? Url.Action(nameof(GetAuditLogs), new { page = page + 1, pageSize, actorUserId, entityType })
            : null;
        var prevLink = page > 1
            ? Url.Action(nameof(GetAuditLogs), new { page = page - 1, pageSize, actorUserId, entityType })
            : null;

        Response.SetPaginationHeaders(totalCount, nextLink, prevLink);

        return Ok(logs);
    }
}
