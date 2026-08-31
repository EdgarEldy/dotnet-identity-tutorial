using FluentValidation;

namespace DotnetIdentityTutorial.Validators;

/// <summary>
/// Shared FluentValidation rules mirroring the exact password policy already configured on
/// <c>AddIdentity&lt;...&gt;()</c> in Program.cs (digit, uppercase, lowercase, minimum length 8,
/// no special character required). Identity's own <c>PasswordValidator</c> would reject a bad
/// password too, but only after a request already reached <c>UserManager</c> - surfacing the
/// same rule here means a bad password comes back as a 400 <c>ValidationProblemDetails</c> from
/// the global <c>ValidationFilter</c> instead, a better experience for the same rule. Kept as one
/// extension method rather than duplicating these four <c>RuleFor</c> calls in every validator
/// that accepts a new password, so the two policies can't silently drift apart from each other.
/// </summary>
public static class PasswordRuleExtensions
{
    public static IRuleBuilderOptions<T, string> MustSatisfyPasswordPolicy<T>(this IRuleBuilder<T, string> ruleBuilder)
    {
        return ruleBuilder
            .NotEmpty()
            .MinimumLength(8)
            .Matches("[0-9]").WithMessage("Password must contain at least one digit.")
            .Matches("[A-Z]").WithMessage("Password must contain at least one uppercase letter.")
            .Matches("[a-z]").WithMessage("Password must contain at least one lowercase letter.");
    }
}
