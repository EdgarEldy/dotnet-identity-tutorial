using Microsoft.AspNetCore.Authorization;

namespace DotnetIdentityTutorial.Authorization;

/// <summary>
/// A single "RESOURCE:ACTION" permission string (e.g. "USER:READ"), required by
/// <see cref="PermissionAuthorizationHandler"/>. One instance is built per policy name by
/// <see cref="PermissionPolicyProvider"/>, so there's no fixed enum/list of permissions to
/// keep in sync - any string an <c>[Authorize(Policy = "...")]</c> attribute names becomes a
/// requirement for exactly that string.
/// </summary>
public sealed class PermissionRequirement : IAuthorizationRequirement
{
    public PermissionRequirement(string permission)
    {
        Permission = permission;
    }

    public string Permission { get; }
}
