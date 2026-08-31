using DotnetIdentityTutorial.Dtos.Rbac;
using DotnetIdentityTutorial.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DotnetIdentityTutorial.Controllers;

/// <summary>
/// Permission administration: list and create. Routing follows the default
/// <c>[controller]</c> convention (<c>/api/v1/Permissions</c>), which is exactly why this needs
/// to be its own controller rather than folded into <see cref="RolesController"/> with a
/// hand-typed route - see "Routing stays on the default convention" in CLAUDE.md. See
/// <see cref="UsersController"/>'s remarks for why every action here carries an
/// <c>[Authorize(Policy = "...")]</c> attribute that doesn't actually resolve yet on this
/// branch.
/// </summary>
[ApiController]
[Route("api/v1/[controller]")]
public sealed class PermissionsController : ControllerBase
{
    private readonly IRbacService _rbacService;

    public PermissionsController(IRbacService rbacService)
    {
        _rbacService = rbacService;
    }

    [HttpGet]
    [Authorize(Policy = "PERMISSION:READ")]
    public async Task<ActionResult<IReadOnlyList<PermissionResponse>>> GetPermissions(CancellationToken cancellationToken)
    {
        var permissions = await _rbacService.GetPermissionsAsync(cancellationToken);
        return Ok(permissions);
    }

    [HttpPost]
    [Authorize(Policy = "PERMISSION:WRITE")]
    public async Task<ActionResult<PermissionResponse>> CreatePermission(PermissionRequest request, CancellationToken cancellationToken)
    {
        var permission = await _rbacService.CreatePermissionAsync(request, cancellationToken);

        // Same reasoning as RolesController.CreateRole: no GET /api/v1/Permissions/{id} exists
        // on this branch's endpoint table, so Location is built directly rather than via
        // CreatedAtAction.
        return Created($"/api/v1/Permissions/{permission.Id}", permission);
    }
}
