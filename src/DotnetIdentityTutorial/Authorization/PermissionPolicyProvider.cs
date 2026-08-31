using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace DotnetIdentityTutorial.Authorization;

/// <summary>
/// Builds an <see cref="AuthorizationPolicy"/> on demand for any policy name an
/// <c>[Authorize(Policy = "RESOURCE:ACTION")]</c> attribute declares, instead of requiring
/// every permission string to be pre-registered against <see cref="AuthorizationOptions"/> up
/// front. This is what lets <c>UsersController</c>/<c>RolesController</c>/
/// <c>PermissionsController</c> (added on feature/rbac) reference policies like "USER:READ" or
/// "PERMISSION:WRITE" without any code here needing to know those strings ahead of time - see
/// the README's "Claims-based authorization" design section.
///
/// Registered as the sole <see cref="IAuthorizationPolicyProvider"/>, replacing the default one
/// (see Program.cs), so <see cref="GetDefaultPolicyAsync"/>/<see cref="GetFallbackPolicyAsync"/>
/// delegate to an internally-constructed <see cref="DefaultAuthorizationPolicyProvider"/> for
/// the cases ASP.NET Core itself still needs, e.g. a parameterless <c>[Authorize]</c>.
/// </summary>
public sealed class PermissionPolicyProvider : IAuthorizationPolicyProvider
{
    private readonly DefaultAuthorizationPolicyProvider _fallbackPolicyProvider;

    public PermissionPolicyProvider(IOptions<AuthorizationOptions> options)
    {
        _fallbackPolicyProvider = new DefaultAuthorizationPolicyProvider(options);
    }

    public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        // RequireAuthenticatedUser() is explicit on purpose rather than relying on the
        // incidental fact that an anonymous principal happens to carry no "permission" claims:
        // that implicit property would stop holding the moment any other authentication
        // handler could attach claims to a principal without also authenticating it.
        var policy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .AddRequirements(new PermissionRequirement(policyName))
            .Build();

        return Task.FromResult<AuthorizationPolicy?>(policy);
    }

    public Task<AuthorizationPolicy> GetDefaultPolicyAsync() => _fallbackPolicyProvider.GetDefaultPolicyAsync();

    public Task<AuthorizationPolicy?> GetFallbackPolicyAsync() => _fallbackPolicyProvider.GetFallbackPolicyAsync();
}
