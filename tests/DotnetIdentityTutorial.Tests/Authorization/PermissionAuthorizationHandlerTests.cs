using System.Security.Claims;
using DotnetIdentityTutorial.Authorization;
using Microsoft.AspNetCore.Authorization;

namespace DotnetIdentityTutorial.Tests.Authorization;

/// <summary>
/// <see cref="PermissionAuthorizationHandler"/> is a pure claims check with no database
/// dependency, so it's exercised directly against an <see cref="AuthorizationHandlerContext"/>
/// built in-memory, without a web host or a real database - see the README's "Claims-based
/// authorization" design section.
/// </summary>
public class PermissionAuthorizationHandlerTests
{
    private static AuthorizationHandlerContext BuildContext(PermissionRequirement requirement, ClaimsPrincipal user)
    {
        return new AuthorizationHandlerContext([requirement], user, resource: null);
    }

    private static ClaimsPrincipal BuildPrincipal(params Claim[] claims)
    {
        var identity = new ClaimsIdentity(claims, "TestAuthType");
        return new ClaimsPrincipal(identity);
    }

    [Fact]
    public async Task HandleRequirementAsync_UserHasMatchingPermissionClaim_Succeeds()
    {
        var requirement = new PermissionRequirement("USER:READ");
        var user = BuildPrincipal(new Claim("permission", "USER:READ"));
        var context = BuildContext(requirement, user);
        var handler = new PermissionAuthorizationHandler();

        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task HandleRequirementAsync_UserMissingPermissionClaim_DoesNotSucceed()
    {
        var requirement = new PermissionRequirement("USER:WRITE");
        var user = BuildPrincipal(new Claim("permission", "USER:READ"));
        var context = BuildContext(requirement, user);
        var handler = new PermissionAuthorizationHandler();

        await handler.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    [Fact]
    public async Task HandleRequirementAsync_UserHasNoClaimsAtAll_DoesNotSucceed()
    {
        var requirement = new PermissionRequirement("USER:READ");
        var user = new ClaimsPrincipal(new ClaimsIdentity());
        var context = BuildContext(requirement, user);
        var handler = new PermissionAuthorizationHandler();

        await handler.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }
}
