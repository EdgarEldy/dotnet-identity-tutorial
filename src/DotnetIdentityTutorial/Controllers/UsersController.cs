using DotnetIdentityTutorial.Dtos.User;
using DotnetIdentityTutorial.Extensions;
using DotnetIdentityTutorial.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DotnetIdentityTutorial.Controllers;

/// <summary>
/// User administration: paginated listing, detail, lock/unlock, and role assignment. Every
/// action carries the <c>[Authorize(Policy = "...")]</c> attribute the README's feature/rbac
/// endpoint table specifies, even though the policy provider that resolves a "RESOURCE:ACTION"
/// string into an actual authorization policy doesn't exist until
/// feature/claims-and-authorization - see that deviation entry in CLAUDE.md. Every request to
/// this controller will fail at request time ("no policy named 'X:Y' was found") until that
/// branch lands; this is expected, not a regression, and is why this branch's own tests exercise
/// <see cref="IUserAdminService"/>/<see cref="IRbacService"/> directly instead of through HTTP.
/// </summary>
[ApiController]
[Route("api/v1/[controller]")]
public sealed class UsersController : ControllerBase
{
    private const int DefaultPageSize = 20;

    private readonly IUserAdminService _userAdminService;
    private readonly IRbacService _rbacService;

    public UsersController(IUserAdminService userAdminService, IRbacService rbacService)
    {
        _userAdminService = userAdminService;
        _rbacService = rbacService;
    }

    [HttpGet]
    [Authorize(Policy = "USER:READ")]
    public async Task<ActionResult<IReadOnlyList<UserResponse>>> GetUsers([FromQuery] int page = 1, [FromQuery] int pageSize = DefaultPageSize, CancellationToken cancellationToken = default)
    {
        var (users, totalCount) = await _userAdminService.GetUsersAsync(page, pageSize, cancellationToken);

        var nextLink = page * pageSize < totalCount
            ? Url.Action(nameof(GetUsers), new { page = page + 1, pageSize })
            : null;
        var prevLink = page > 1
            ? Url.Action(nameof(GetUsers), new { page = page - 1, pageSize })
            : null;

        Response.SetPaginationHeaders(totalCount, nextLink, prevLink);

        return Ok(users);
    }

    [HttpGet("{id:int}")]
    [Authorize(Policy = "USER:READ")]
    public async Task<ActionResult<UserResponse>> GetUser(int id, CancellationToken cancellationToken)
    {
        var user = await _userAdminService.GetUserByIdAsync(id, cancellationToken);
        return Ok(user);
    }

    [HttpPatch("{id:int}/Lock")]
    [Authorize(Policy = "USER:WRITE")]
    public async Task<IActionResult> Lock(int id, CancellationToken cancellationToken)
    {
        await _userAdminService.LockUserAsync(id, cancellationToken);
        return NoContent();
    }

    [HttpPatch("{id:int}/Unlock")]
    [Authorize(Policy = "USER:WRITE")]
    public async Task<IActionResult> Unlock(int id, CancellationToken cancellationToken)
    {
        await _userAdminService.UnlockUserAsync(id, cancellationToken);
        return NoContent();
    }

    [HttpPost("{id:int}/Roles/{roleId:int}")]
    [Authorize(Policy = "USER:WRITE")]
    public async Task<IActionResult> AssignRole(int id, int roleId, CancellationToken cancellationToken)
    {
        await _rbacService.AssignRoleToUserAsync(id, roleId, cancellationToken);
        return NoContent();
    }

    [HttpDelete("{id:int}/Roles/{roleId:int}")]
    [Authorize(Policy = "USER:WRITE")]
    public async Task<IActionResult> RemoveRole(int id, int roleId, CancellationToken cancellationToken)
    {
        await _rbacService.RemoveRoleFromUserAsync(id, roleId, cancellationToken);
        return NoContent();
    }
}
