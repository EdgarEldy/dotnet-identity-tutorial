using DotnetIdentityTutorial.Dtos.Auth;
using FluentValidation;

namespace DotnetIdentityTutorial.Validators;

public sealed class RefreshRequestValidator : AbstractValidator<RefreshRequest>
{
    public RefreshRequestValidator()
    {
        RuleFor(x => x.RefreshToken)
            .NotEmpty();
    }
}
