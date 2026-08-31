using DotnetIdentityTutorial.Dtos.Rbac;
using FluentValidation;

namespace DotnetIdentityTutorial.Validators;

/// <summary>
/// Enforces the same <c>RESOURCE:ACTION</c> naming convention the seeded baseline permissions
/// already follow (<c>USER:READ</c>, <c>ROLE:WRITE</c>, ...): both <see cref="PermissionRequest.Resource"/>
/// and <see cref="PermissionRequest.Action"/> are uppercase letters, digits, or underscores,
/// starting with a letter, since the pair is concatenated with a colon to form the policy name
/// <c>[Authorize(Policy = "RESOURCE:ACTION")]</c> resolves once feature/claims-and-authorization
/// lands.
/// </summary>
public sealed class PermissionRequestValidator : AbstractValidator<PermissionRequest>
{
    public PermissionRequestValidator()
    {
        RuleFor(x => x.Resource)
            .NotEmpty()
            .MaximumLength(50)
            .Matches("^[A-Z][A-Z0-9_]*$")
            .WithMessage("Resource must be uppercase letters, digits, or underscores, starting with a letter (e.g. \"USER\").");

        RuleFor(x => x.Action)
            .NotEmpty()
            .MaximumLength(50)
            .Matches("^[A-Z][A-Z0-9_]*$")
            .WithMessage("Action must be uppercase letters, digits, or underscores, starting with a letter (e.g. \"READ\").");
    }
}
