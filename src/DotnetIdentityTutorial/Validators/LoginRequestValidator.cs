using DotnetIdentityTutorial.Dtos.Auth;
using FluentValidation;

namespace DotnetIdentityTutorial.Validators;

public sealed class LoginRequestValidator : AbstractValidator<LoginRequest>
{
    public LoginRequestValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty()
            .EmailAddress();

        // Intentionally no MustSatisfyPasswordPolicy() here: this would tell an attacker
        // whether a login attempt failed on validation shape versus actual credential mismatch,
        // and a login's password doesn't need to satisfy today's policy anyway (an account
        // created under a looser historical policy must still be able to sign in).
        RuleFor(x => x.Password)
            .NotEmpty();
    }
}
