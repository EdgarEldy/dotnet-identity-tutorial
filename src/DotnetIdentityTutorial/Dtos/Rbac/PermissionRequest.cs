namespace DotnetIdentityTutorial.Dtos.Rbac;

/// <summary>
/// The body of <c>POST /api/v1/Permissions</c>. Validated by <c>PermissionRequestValidator</c>.
/// </summary>
public record PermissionRequest(string Resource, string Action);
