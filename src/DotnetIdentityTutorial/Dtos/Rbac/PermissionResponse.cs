namespace DotnetIdentityTutorial.Dtos.Rbac;

/// <summary>
/// The shape returned by <c>GET /api/v1/Permissions</c>, <c>POST /api/v1/Permissions</c>, and
/// embedded in <see cref="RoleResponse"/>.
/// </summary>
public record PermissionResponse(int Id, string Resource, string Action);
