using DotnetIdentityTutorial.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.Extensions.Options;

namespace DotnetIdentityTutorial.Tests.Authorization;

/// <summary>
/// Proves <see cref="PermissionPolicyProvider"/> is genuinely dynamic: it builds a policy for
/// any permission string handed to it, without any hardcoded lookup table of known policy
/// names. The permission string used here is deliberately arbitrary and appears nowhere else
/// in the codebase, so a passing test can't be explained by a coincidental pre-registration.
/// </summary>
public class PermissionPolicyProviderTests
{
    private static PermissionPolicyProvider BuildProvider()
    {
        var options = Options.Create(new AuthorizationOptions());
        return new PermissionPolicyProvider(options);
    }

    [Fact]
    public async Task GetPolicyAsync_ArbitraryPermissionString_ReturnsPolicyWithMatchingRequirement()
    {
        var provider = BuildProvider();
        const string arbitraryPermission = "WIDGET:FROBNICATE";

        var policy = await provider.GetPolicyAsync(arbitraryPermission);

        Assert.NotNull(policy);
        var requirement = Assert.Single(policy!.Requirements.OfType<PermissionRequirement>());
        Assert.Equal(arbitraryPermission, requirement.Permission);
    }

    [Fact]
    public async Task GetPolicyAsync_ReturnsPolicyThatAlsoRequiresAnAuthenticatedUser()
    {
        var provider = BuildProvider();

        var policy = await provider.GetPolicyAsync("WIDGET:FROBNICATE");

        Assert.Contains(policy!.Requirements, r => r is DenyAnonymousAuthorizationRequirement);
    }

    [Fact]
    public async Task GetDefaultPolicyAsync_StillRequiresAnAuthenticatedUser()
    {
        var provider = BuildProvider();

        var policy = await provider.GetDefaultPolicyAsync();

        Assert.Contains(policy.Requirements, r => r is DenyAnonymousAuthorizationRequirement);
    }

    [Fact]
    public async Task GetPolicyAsync_TwoDifferentPermissionStrings_ReturnDistinctRequirements()
    {
        var provider = BuildProvider();

        var firstPolicy = await provider.GetPolicyAsync("ORDER:READ");
        var secondPolicy = await provider.GetPolicyAsync("ORDER:WRITE");

        var firstRequirement = Assert.Single(firstPolicy!.Requirements.OfType<PermissionRequirement>());
        var secondRequirement = Assert.Single(secondPolicy!.Requirements.OfType<PermissionRequirement>());
        Assert.Equal("ORDER:READ", firstRequirement.Permission);
        Assert.Equal("ORDER:WRITE", secondRequirement.Permission);
    }

    [Fact]
    public async Task GetFallbackPolicyAsync_DelegatesToDefaultProvider_DoesNotThrow()
    {
        var provider = BuildProvider();

        var exception = await Record.ExceptionAsync(() => provider.GetFallbackPolicyAsync());

        Assert.Null(exception);
    }
}
