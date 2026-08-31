namespace DotnetIdentityTutorial.Dtos.Rbac;

/// <summary>
/// The body of <c>POST /api/v1/Roles</c>. Validated by <c>RoleRequestValidator</c>.
/// </summary>
public record RoleRequest(string Name);
