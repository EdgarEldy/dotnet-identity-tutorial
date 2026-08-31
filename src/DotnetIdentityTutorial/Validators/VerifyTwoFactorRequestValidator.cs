using DotnetIdentityTutorial.Dtos.Auth;
using FluentValidation;

namespace DotnetIdentityTutorial.Validators;

public sealed class VerifyTwoFactorRequestValidator : AbstractValidator<VerifyTwoFactorRequest>
{
    public VerifyTwoFactorRequestValidator()
    {
        RuleFor(x => x.TwoFactorToken)
            .NotEmpty();

        // No digits-only Matches() rule here, unlike Confirm2faRequestValidator - Code can be
        // either a 6-digit TOTP code or a recovery code (a longer alphanumeric value Identity
        // generates), and AuthService.VerifyTwoFactorAsync tries both without knowing in advance
        // which shape it is.
        RuleFor(x => x.Code)
            .NotEmpty();
    }
}
