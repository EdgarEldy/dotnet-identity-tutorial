using DotnetIdentityTutorial.Data;
using DotnetIdentityTutorial.Dtos.Rbac;
using DotnetIdentityTutorial.Exceptions;
using DotnetIdentityTutorial.Identity;
using DotnetIdentityTutorial.Models;
using DotnetIdentityTutorial.Services.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace DotnetIdentityTutorial.Services.Implementations;

/// <summary>
/// The one place allowed to call <c>RoleManager&lt;ApplicationRole&gt;</c>,
/// <c>UserManager&lt;ApplicationUser&gt;</c>, and <c>AppDbContext</c> directly for role/permission
/// administration - everywhere else in the request pipeline goes through <see cref="IRbacService"/>
/// instead, per the "Identity managers are always wrapped" rule. Unlike <c>DbInitializer</c>,
/// this class is reached from a real HTTP request (once feature/claims-and-authorization makes
/// the <c>[Authorize(Policy = ...)]</c> attributes on the controllers actually resolve), so it
/// does not get that same bootstrap-code exception.
///
/// Assignment/removal idempotency: assigning a permission/role that's already assigned, or
/// removing one that isn't, is treated as a silent no-op rather than a 422 - re-running the same
/// "make it so" request should never fail just because it already succeeded once, and this
/// matches how <c>DbInitializer</c>'s own seeding already behaves for the same tables. The
/// role/permission/user ids themselves still have to exist (<see cref="ResourceNotFoundException"/>
/// otherwise) - only the *relationship* is idempotent. Creating a duplicate role name or a
/// duplicate (Resource, Action) permission pair, on the other hand, is a
/// <see cref="BusinessRuleException"/> (422): those are user-facing "create" operations where
/// silently returning the existing row would hide a real naming collision from the caller
/// instead of surfacing it.
/// </summary>
public sealed class RbacService : IRbacService
{
    private readonly AppDbContext _dbContext;
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAuditService _auditService;

    public RbacService(
        AppDbContext dbContext,
        RoleManager<ApplicationRole> roleManager,
        UserManager<ApplicationUser> userManager,
        IAuditService auditService)
    {
        _dbContext = dbContext;
        _roleManager = roleManager;
        _userManager = userManager;
        _auditService = auditService;
    }

    public async Task<IReadOnlyList<PermissionResponse>> GetPermissionsAsync(CancellationToken cancellationToken = default)
    {
        return await _dbContext.Permissions
            .OrderBy(p => p.Resource)
            .ThenBy(p => p.Action)
            .Select(p => new PermissionResponse(p.Id, p.Resource, p.Action))
            .ToListAsync(cancellationToken);
    }

    public async Task<PermissionResponse> CreatePermissionAsync(PermissionRequest request, CancellationToken cancellationToken = default)
    {
        var alreadyExists = await _dbContext.Permissions
            .AnyAsync(p => p.Resource == request.Resource && p.Action == request.Action, cancellationToken);
        if (alreadyExists)
        {
            throw new BusinessRuleException($"Permission '{request.Resource}:{request.Action}' already exists.");
        }

        var permission = new Permission { Resource = request.Resource, Action = request.Action };
        _dbContext.Permissions.Add(permission);
        await _dbContext.SaveChangesAsync(cancellationToken);

        await _auditService.LogAsync(
            "Create",
            nameof(Permission),
            permission.Id.ToString(),
            new { permission.Resource, permission.Action });

        return new PermissionResponse(permission.Id, permission.Resource, permission.Action);
    }

    public async Task<IReadOnlyList<RoleResponse>> GetRolesAsync(CancellationToken cancellationToken = default)
    {
        var roles = await _dbContext.Roles
            .Include(r => r.RolePermissions)
            .ThenInclude(rp => rp.Permission)
            .OrderBy(r => r.Name)
            .ToListAsync(cancellationToken);

        return roles
            .Select(r => new RoleResponse(
                r.Id,
                r.Name!,
                r.RolePermissions
                    .Select(rp => new PermissionResponse(rp.Permission.Id, rp.Permission.Resource, rp.Permission.Action))
                    .OrderBy(p => p.Resource)
                    .ThenBy(p => p.Action)
                    .ToList()))
            .ToList();
    }

    public async Task<RoleResponse> CreateRoleAsync(RoleRequest request, CancellationToken cancellationToken = default)
    {
        if (await _roleManager.RoleExistsAsync(request.Name))
        {
            throw new BusinessRuleException($"Role '{request.Name}' already exists.");
        }

        var role = new ApplicationRole { Name = request.Name };
        var result = await _roleManager.CreateAsync(role);
        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            throw new BusinessRuleException($"Failed to create role '{request.Name}': {errors}");
        }

        await _auditService.LogAsync("Create", nameof(ApplicationRole), role.Id.ToString(), new { role.Name });

        return new RoleResponse(role.Id, role.Name!, []);
    }

    public async Task AssignPermissionToRoleAsync(int roleId, int permissionId, CancellationToken cancellationToken = default)
    {
        await EnsureRoleExistsAsync(roleId, cancellationToken);
        await EnsurePermissionExistsAsync(permissionId, cancellationToken);

        var alreadyAssigned = await _dbContext.RolePermissions
            .AnyAsync(rp => rp.RoleId == roleId && rp.PermissionId == permissionId, cancellationToken);
        if (!alreadyAssigned)
        {
            _dbContext.RolePermissions.Add(new RolePermission { RoleId = roleId, PermissionId = permissionId });
            await _dbContext.SaveChangesAsync(cancellationToken);
        }

        await _auditService.LogAsync(
            "AssignPermission",
            nameof(ApplicationRole),
            roleId.ToString(),
            new { PermissionId = permissionId });
    }

    public async Task RemovePermissionFromRoleAsync(int roleId, int permissionId, CancellationToken cancellationToken = default)
    {
        await EnsureRoleExistsAsync(roleId, cancellationToken);
        await EnsurePermissionExistsAsync(permissionId, cancellationToken);

        var existing = await _dbContext.RolePermissions
            .SingleOrDefaultAsync(rp => rp.RoleId == roleId && rp.PermissionId == permissionId, cancellationToken);
        if (existing is not null)
        {
            _dbContext.RolePermissions.Remove(existing);
            await _dbContext.SaveChangesAsync(cancellationToken);
        }

        await _auditService.LogAsync(
            "RemovePermission",
            nameof(ApplicationRole),
            roleId.ToString(),
            new { PermissionId = permissionId });
    }

    public async Task AssignRoleToUserAsync(int userId, int roleId, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString())
            ?? throw new ResourceNotFoundException($"User {userId} was not found.");
        var role = await EnsureRoleExistsAsync(roleId, cancellationToken);

        if (!await _userManager.IsInRoleAsync(user, role.Name!))
        {
            var result = await _userManager.AddToRoleAsync(user, role.Name!);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                throw new BusinessRuleException($"Failed to assign role '{role.Name}' to user {userId}: {errors}");
            }
        }

        await _auditService.LogAsync("AssignRole", "User", userId.ToString(), new { RoleId = roleId });
    }

    public async Task RemoveRoleFromUserAsync(int userId, int roleId, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString())
            ?? throw new ResourceNotFoundException($"User {userId} was not found.");
        var role = await EnsureRoleExistsAsync(roleId, cancellationToken);

        if (await _userManager.IsInRoleAsync(user, role.Name!))
        {
            var result = await _userManager.RemoveFromRoleAsync(user, role.Name!);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                throw new BusinessRuleException($"Failed to remove role '{role.Name}' from user {userId}: {errors}");
            }
        }

        await _auditService.LogAsync("RemoveRole", "User", userId.ToString(), new { RoleId = roleId });
    }

    private async Task<ApplicationRole> EnsureRoleExistsAsync(int roleId, CancellationToken cancellationToken)
    {
        return await _dbContext.Roles.SingleOrDefaultAsync(r => r.Id == roleId, cancellationToken)
            ?? throw new ResourceNotFoundException($"Role {roleId} was not found.");
    }

    private async Task EnsurePermissionExistsAsync(int permissionId, CancellationToken cancellationToken)
    {
        var exists = await _dbContext.Permissions.AnyAsync(p => p.Id == permissionId, cancellationToken);
        if (!exists)
        {
            throw new ResourceNotFoundException($"Permission {permissionId} was not found.");
        }
    }
}
