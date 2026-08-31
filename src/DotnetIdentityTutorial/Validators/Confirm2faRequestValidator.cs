using DotnetIdentityTutorial.Dtos.Auth;
using FluentValidation;

namespace DotnetIdentityTutorial.Validators;

public sealed class Confirm2faRequestValidator : AbstractValidator<Confirm2faRequest>
{
    public Confirm2faRequestValidator()
    {
        // A TOTP code is always exactly 6 digits - unlike VerifyTwoFactorRequestValidator's own
        // Code field, this one is never a recovery code, Confirm2fa only ever verifies the first
        // code generated from a freshly issued authenticator secret during initial setup.
        RuleFor(x => x.Code)
            .NotEmpty()
            .Matches(@"^\d{6}$")
            .WithMessage("Code must be a 6-digit authenticator code.");
    }
}
