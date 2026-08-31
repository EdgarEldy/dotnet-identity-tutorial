using DotnetIdentityTutorial.Dtos.Auth;
using FluentValidation;

namespace DotnetIdentityTutorial.Validators;

public sealed class ResetPasswordRequestValidator : AbstractValidator<ResetPasswordRequest>
{
    public ResetPasswordRequestValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty()
            .EmailAddress();

        RuleFor(x => x.Token)
            .NotEmpty();

        RuleFor(x => x.NewPassword)
            .MustSatisfyPasswordPolicy();
    }
}
