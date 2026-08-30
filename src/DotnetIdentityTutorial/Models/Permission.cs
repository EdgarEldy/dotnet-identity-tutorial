namespace DotnetIdentityTutorial.Models;

/// <summary>
/// A single resource/action pair (e.g. <c>Resource = "USER"</c>, <c>Action = "READ"</c>),
/// used as the policy name for <c>[Authorize(Policy = "USER:READ")]</c> once
/// <c>feature/claims-and-authorization</c> wires the claims-based policy provider. Fluent
/// API configuration lives in <see cref="Configurations.PermissionConfiguration"/>, not
/// data annotations here.
/// </summary>
public class Permission
{
    public int Id { get; set; }

    public required string Resource { get; set; }

    public required string Action { get; set; }
}
