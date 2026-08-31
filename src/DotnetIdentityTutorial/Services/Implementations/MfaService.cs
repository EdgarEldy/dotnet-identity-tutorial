using DotnetIdentityTutorial.Dtos.Auth;
using DotnetIdentityTutorial.Exceptions;
using DotnetIdentityTutorial.Identity;
using DotnetIdentityTutorial.Services.Interfaces;
using Microsoft.AspNetCore.Identity;

namespace DotnetIdentityTutorial.Services.Implementations;

/// <inheritdoc cref="IMfaService"/>
public sealed class MfaService : IMfaService
{
    /// <summary>
    /// The issuer label embedded in the generated <c>otpauth://</c> URI - what an authenticator
    /// app displays next to the account entry it creates. Not read from configuration: this is
    /// purely a display label, not a secret or an environment-specific value.
    /// </summary>
    private const string IssuerLabel = "DotnetIdentityTutorial";

    /// <summary>
    /// How many recovery codes <see cref="Confirm2faAsync"/> generates the moment 2FA is
    /// activated - Identity's own recommended default.
    /// </summary>
    private const int RecoveryCodeCount = 10;

    private readonly UserManager<ApplicationUser> _userManager;

    public MfaService(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task<Enable2faResponse> Enable2faAsync(int userId, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString())
            ?? throw new ResourceNotFoundException($"User {userId} was not found.");

        var sharedKey = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(sharedKey))
        {
            // Only reset when there is no key yet - the standard idempotent Identity 2FA setup
            // pattern. Resetting unconditionally here would invalidate a QR code the user may
            // have already scanned every time they reload the setup page before confirming it.
            await _userManager.ResetAuthenticatorKeyAsync(user);
            sharedKey = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        var authenticatorUri = BuildAuthenticatorUri(user.Email ?? user.UserName ?? userId.ToString(), sharedKey!);

        return new Enable2faResponse(sharedKey!, authenticatorUri);
    }

    public async Task<Confirm2faResponse> Confirm2faAsync(int userId, Confirm2faRequest request, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString())
            ?? throw new ResourceNotFoundException($"User {userId} was not found.");

        var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, request.Code);
        if (!isValid)
        {
            throw new BusinessRuleException("Invalid authenticator code.");
        }

        await _userManager.SetTwoFactorEnabledAsync(user, true);

        var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, RecoveryCodeCount);

        return new Confirm2faResponse((recoveryCodes ?? Enumerable.Empty<string>()).ToList());
    }

    public async Task Disable2faAsync(int userId, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString())
            ?? throw new ResourceNotFoundException($"User {userId} was not found.");

        await _userManager.SetTwoFactorEnabledAsync(user, false);

        // Also resets the authenticator key, not just the enabled flag - so a future re-enable
        // always starts from a brand-new secret instead of silently reusing one that may have
        // been the reason 2FA was turned off in the first place (e.g. a compromised device).
        await _userManager.ResetAuthenticatorKeyAsync(user);
    }

    private static string BuildAuthenticatorUri(string label, string sharedKey)
    {
        return $"otpauth://totp/{Uri.EscapeDataString(label)}" +
               $"?secret={Uri.EscapeDataString(sharedKey)}" +
               $"&issuer={Uri.EscapeDataString(IssuerLabel)}" +
               "&digits=6";
    }
}
