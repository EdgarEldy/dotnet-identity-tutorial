using DotnetIdentityTutorial.Dtos.Rbac;
using FluentValidation;

namespace DotnetIdentityTutorial.Validators;

/// <summary>
/// Enforces the same naming convention the seeded roles already follow (<c>ADMIN</c>,
/// <c>USER</c>): uppercase letters, digits, or underscores, starting with a letter. Role names
/// double as the string embedded in a future JWT's <c>role</c> claim, so keeping them
/// predictable and shout-cased avoids a mix of casing conventions across roles created later
/// through this endpoint versus the ones seeded at startup.
/// </summary>
public sealed class RoleRequestValidator : AbstractValidator<RoleRequest>
{
    public RoleRequestValidator()
    {
        RuleFor(x => x.Name)
            .NotEmpty()
            .MaximumLength(50)
            .Matches("^[A-Z][A-Z0-9_]*$")
            .WithMessage("Name must be uppercase letters, digits, or underscores, starting with a letter (e.g. \"ADMIN\").");
    }
}
