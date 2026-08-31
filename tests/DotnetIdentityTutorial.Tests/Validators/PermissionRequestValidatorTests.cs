using DotnetIdentityTutorial.Dtos.Rbac;
using DotnetIdentityTutorial.Validators;

namespace DotnetIdentityTutorial.Tests.Validators;

/// <summary>
/// Plain unit tests against <see cref="PermissionRequestValidator"/> directly - no database, no
/// <see cref="DotnetIdentityTutorial.Filters.ValidationFilter"/> involved.
/// </summary>
public class PermissionRequestValidatorTests
{
    private readonly PermissionRequestValidator _validator = new();

    [Theory]
    [InlineData("USER", "READ")]
    [InlineData("ROLE", "WRITE")]
    [InlineData("AUDIT_LOG", "READ")]
    public void Validate_WellFormedResourceAndAction_Passes(string resource, string action)
    {
        var result = _validator.Validate(new PermissionRequest(resource, action));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_EmptyResource_Fails()
    {
        var result = _validator.Validate(new PermissionRequest(string.Empty, "READ"));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.PropertyName == nameof(PermissionRequest.Resource));
    }

    [Fact]
    public void Validate_EmptyAction_Fails()
    {
        var result = _validator.Validate(new PermissionRequest("USER", string.Empty));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.PropertyName == nameof(PermissionRequest.Action));
    }

    [Theory]
    [InlineData("user", "READ")]
    [InlineData("USER", "read")]
    [InlineData("USER:READ", "READ")]
    [InlineData("1USER", "READ")]
    public void Validate_MalformedResourceOrAction_Fails(string resource, string action)
    {
        var result = _validator.Validate(new PermissionRequest(resource, action));

        Assert.False(result.IsValid);
    }
}
