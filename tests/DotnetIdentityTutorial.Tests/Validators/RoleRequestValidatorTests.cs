using DotnetIdentityTutorial.Dtos.Rbac;
using DotnetIdentityTutorial.Validators;

namespace DotnetIdentityTutorial.Tests.Validators;

/// <summary>
/// Plain unit tests against <see cref="RoleRequestValidator"/> directly - no database, no
/// <see cref="DotnetIdentityTutorial.Filters.ValidationFilter"/> involved, since the validator's
/// own rules are what's under test here.
/// </summary>
public class RoleRequestValidatorTests
{
    private readonly RoleRequestValidator _validator = new();

    [Theory]
    [InlineData("ADMIN")]
    [InlineData("USER")]
    [InlineData("SUPPORT_AGENT")]
    [InlineData("A")]
    public void Validate_WellFormedName_Passes(string name)
    {
        var result = _validator.Validate(new RoleRequest(name));

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_EmptyName_Fails()
    {
        var result = _validator.Validate(new RoleRequest(string.Empty));

        Assert.False(result.IsValid);
    }

    [Theory]
    [InlineData("admin")]
    [InlineData("Admin")]
    [InlineData("1ADMIN")]
    [InlineData("ADMIN-ROLE")]
    [InlineData("ADMIN ROLE")]
    public void Validate_MalformedName_Fails(string name)
    {
        var result = _validator.Validate(new RoleRequest(name));

        Assert.False(result.IsValid);
    }

    [Fact]
    public void Validate_NameExceedsMaxLength_Fails()
    {
        var name = new string('A', 51);

        var result = _validator.Validate(new RoleRequest(name));

        Assert.False(result.IsValid);
    }
}
