using Microsoft.AspNetCore.Authorization;

namespace DotnetIdentityTutorial.Authorization;

/// <summary>
/// A single "RESOURCE:ACTION" permission string (e.g. "USER:READ"), required by
/// <see cref="PermissionAuthorizationHandler"/>. One instance is built per policy name by
/// <see cref="PermissionPolicyProvider"/>, so there's no fixed enum/list of permissions to
/// keep in sync - any string an <c>[Authorize(Policy = "...")]</c> attribute names becomes a
/// requirement for exactly that string.
/// </summary>
public sealed record PermissionRequirement(string Permission) : IAuthorizationRequirement
{
    /// <summary>
    /// The claim type <see cref="Identity.ApplicationUserClaimsPrincipalFactory"/> writes and
    /// <see cref="PermissionAuthorizationHandler"/> reads. Defined once here so the two can
    /// never silently drift apart, unlike two independent string literals would.
    /// </summary>
    public const string ClaimType = "permission";
}
