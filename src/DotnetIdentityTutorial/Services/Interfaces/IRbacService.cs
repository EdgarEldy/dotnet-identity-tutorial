using DotnetIdentityTutorial.Dtos.Rbac;

namespace DotnetIdentityTutorial.Services.Interfaces;

/// <summary>
/// Wraps <c>RoleManager&lt;ApplicationRole&gt;</c>, <c>UserManager&lt;ApplicationUser&gt;</c>,
/// and the custom <c>Permission</c>/<c>RolePermission</c> tables behind a single contract:
/// permission CRUD, role CRUD (including each role's currently assigned permissions), and the
/// two assignment relationships this branch introduces - permission-to-role and role-to-user.
///
/// Idempotency policy (see <c>RbacService</c> for the reasoning): assigning a permission/role
/// that is already assigned, or removing one that isn't, is a silent no-op, not an error. The
/// role/permission/user id itself still has to exist, a <c>ResourceNotFoundException</c> is
/// thrown otherwise. Creating a role or permission that already exists by name/(Resource,
/// Action) is a <c>BusinessRuleException</c>.
/// </summary>
public interface IRbacService
{
    Task<IReadOnlyList<PermissionResponse>> GetPermissionsAsync(CancellationToken cancellationToken = default);

    Task<PermissionResponse> CreatePermissionAsync(PermissionRequest request, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<RoleResponse>> GetRolesAsync(CancellationToken cancellationToken = default);

    Task<RoleResponse> CreateRoleAsync(RoleRequest request, CancellationToken cancellationToken = default);

    Task AssignPermissionToRoleAsync(int roleId, int permissionId, CancellationToken cancellationToken = default);

    Task RemovePermissionFromRoleAsync(int roleId, int permissionId, CancellationToken cancellationToken = default);

    Task AssignRoleToUserAsync(int userId, int roleId, CancellationToken cancellationToken = default);

    Task RemoveRoleFromUserAsync(int userId, int roleId, CancellationToken cancellationToken = default);
}
