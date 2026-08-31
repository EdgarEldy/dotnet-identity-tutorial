using DotnetIdentityTutorial.Dtos.Auth;
using FluentValidation;

namespace DotnetIdentityTutorial.Validators;

public sealed class ChangePasswordRequestValidator : AbstractValidator<ChangePasswordRequest>
{
    public ChangePasswordRequestValidator()
    {
        RuleFor(x => x.CurrentPassword)
            .NotEmpty();

        RuleFor(x => x.NewPassword)
            .MustSatisfyPasswordPolicy();
    }
}
