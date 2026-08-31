using DotnetIdentityTutorial.Exceptions;
using Microsoft.AspNetCore.Identity;

namespace DotnetIdentityTutorial.Extensions;

/// <summary>
/// Shared translation from a failed <see cref="IdentityResult"/> to this project's own
/// <see cref="BusinessRuleException"/> - every <c>Services/Implementations</c> class that calls
/// an Identity manager method returning <see cref="IdentityResult"/> uses this instead of
/// checking <c>.Succeeded</c> by hand, so a failure can never be silently discarded.
/// </summary>
public static class IdentityResultExtensions
{
    public static void ThrowIfFailed(this IdentityResult result, string action)
    {
        if (result.Succeeded)
        {
            return;
        }

        var errors = string.Join(", ", result.Errors.Select(e => e.Description));
        throw new BusinessRuleException($"{action} failed: {errors}");
    }
}
