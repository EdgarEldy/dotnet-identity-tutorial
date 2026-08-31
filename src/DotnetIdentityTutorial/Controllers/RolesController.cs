using DotnetIdentityTutorial.Dtos.Rbac;
using DotnetIdentityTutorial.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DotnetIdentityTutorial.Controllers;

/// <summary>
/// Role administration: list (including each role's assigned permissions), create, and
/// permission assignment. See <see cref="UsersController"/>'s remarks for why every action here
/// carries an <c>[Authorize(Policy = "...")]</c> attribute that doesn't actually resolve yet on
/// this branch.
/// </summary>
[ApiController]
[Route("api/v1/[controller]")]
public sealed class RolesController : ControllerBase
{
    private readonly IRbacService _rbacService;

    public RolesController(IRbacService rbacService)
    {
        _rbacService = rbacService;
    }

    [HttpGet]
    [Authorize(Policy = "ROLE:READ")]
    public async Task<ActionResult<IReadOnlyList<RoleResponse>>> GetRoles(CancellationToken cancellationToken)
    {
        var roles = await _rbacService.GetRolesAsync(cancellationToken);
        return Ok(roles);
    }

    [HttpPost]
    [Authorize(Policy = "ROLE:WRITE")]
    public async Task<ActionResult<RoleResponse>> CreateRole(RoleRequest request, CancellationToken cancellationToken)
    {
        var role = await _rbacService.CreateRoleAsync(request, cancellationToken);

        // This branch's endpoint table has no GET /api/v1/Roles/{id}, only the list endpoint,
        // so there is no action for CreatedAtAction to reference - the Location header is built
        // directly instead, pointing at the resource's logical URL under this same controller's
        // route.
        return Created($"/api/v1/Roles/{role.Id}", role);
    }

    [HttpPost("{id:int}/Permissions/{permissionId:int}")]
    [Authorize(Policy = "ROLE:WRITE")]
    public async Task<IActionResult> AssignPermission(int id, int permissionId, CancellationToken cancellationToken)
    {
        await _rbacService.AssignPermissionToRoleAsync(id, permissionId, cancellationToken);
        return NoContent();
    }

    [HttpDelete("{id:int}/Permissions/{permissionId:int}")]
    [Authorize(Policy = "ROLE:WRITE")]
    public async Task<IActionResult> RemovePermission(int id, int permissionId, CancellationToken cancellationToken)
    {
        await _rbacService.RemovePermissionFromRoleAsync(id, permissionId, cancellationToken);
        return NoContent();
    }
}
