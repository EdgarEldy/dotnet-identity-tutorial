using Microsoft.AspNetCore.Authorization;

namespace DotnetIdentityTutorial.Authorization;

/// <summary>
/// A pure claims check, no database dependency at request time: permissions were already
/// resolved once, at sign-in time, into "permission" claims by
/// <see cref="Identity.ApplicationUserClaimsPrincipalFactory"/> and baked into the access
/// token. This handler just looks for the exact claim, it never re-queries RolePermission.
/// </summary>
public sealed class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirement>
{
    private const string PermissionClaimType = "permission";

    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PermissionRequirement requirement)
    {
        if (context.User.HasClaim(PermissionClaimType, requirement.Permission))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
