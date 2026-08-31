namespace DotnetIdentityTutorial.Dtos.Rbac;

/// <summary>
/// The shape returned by <c>GET /api/v1/Roles</c> and <c>POST /api/v1/Roles</c>. Carries the
/// full list of permissions currently assigned to the role (empty for a just-created role)
/// rather than just permission id/name strings, so a caller doesn't need a follow-up request to
/// see what a role actually grants.
/// </summary>
public record RoleResponse(int Id, string Name, IReadOnlyList<PermissionResponse> Permissions);
