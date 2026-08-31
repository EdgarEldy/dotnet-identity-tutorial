using System.Security.Claims;
using DotnetIdentityTutorial.Dtos.Auth;
using DotnetIdentityTutorial.Exceptions;
using DotnetIdentityTutorial.Extensions;
using DotnetIdentityTutorial.Identity;
using DotnetIdentityTutorial.Services.Interfaces;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;

namespace DotnetIdentityTutorial.Services.Implementations;

/// <summary>
/// The one place allowed to call <see cref="SignInManager{TUser}"/>/<see cref="UserManager{TUser}"/>
/// for the external-login flow - see <see cref="IExternalLoginService"/>'s own remarks.
/// </summary>
public sealed class ExternalLoginService : IExternalLoginService
{
    /// <summary>
    /// Same default role every self-registered account gets via <c>AuthService.RegisterAsync</c> -
    /// a brand-new account created through Google sign-in is otherwise indistinguishable from one
    /// created through <c>POST /Auth/Register</c>, so it gets the same baseline permissions.
    /// </summary>
    private const string DefaultRoleName = "USER";

    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ITokenService _tokenService;
    private readonly IAuditService _auditService;

    public ExternalLoginService(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        ITokenService tokenService,
        IAuditService auditService)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _tokenService = tokenService;
        _auditService = auditService;
    }

    public AuthenticationProperties BuildChallengeProperties(string redirectUrl)
        => _signInManager.ConfigureExternalAuthenticationProperties(GoogleDefaults.AuthenticationScheme, redirectUrl);

    public Task<ExternalLoginInfo?> GetExternalLoginInfoAsync()
        => _signInManager.GetExternalLoginInfoAsync();

    public async Task<TokenResponse> HandleExternalLoginCallbackAsync(ExternalLoginInfo info, CancellationToken cancellationToken = default)
    {
        // A returning user who already linked this exact Google account - the common case once
        // an account exists, resolved with a single lookup on the (LoginProvider, ProviderKey)
        // pair Identity's own AspNetUserLogins table stores.
        var existingLinkedUser = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
        if (existingLinkedUser is not null)
        {
            return await _tokenService.IssueTokensAsync(existingLinkedUser, cancellationToken);
        }

        // No link yet - Google always supplies an email claim when the standard "email" scope is
        // requested, but this is provider-supplied data, not something to assume blindly.
        var email = info.Principal.FindFirstValue(ClaimTypes.Email)
            ?? throw new BusinessRuleException("The external login provider did not supply an email address.");

        var user = await _userManager.FindByEmailAsync(email);
        if (user is not null)
        {
            // An account with this email already exists - a user who registered with a password
            // first, now signing in with Google for the first time. Link the external login to
            // that existing account rather than trying to create a second one: UserManager.CreateAsync
            // would reject a duplicate email/username outright, so without this explicit branch
            // the whole flow would be broken for any returning password user trying Google for the
            // first time. This is standard, expected external-login behavior - one person, one
            // account, reachable through more than one credential - not scope creep beyond what
            // the README asks for.
            var addLoginResult = await _userManager.AddLoginAsync(user, info);
            addLoginResult.ThrowIfFailed("Linking external login");

            return await _tokenService.IssueTokensAsync(user, cancellationToken);
        }

        // No account at all - create a brand-new one. EmailConfirmed is set true outright: Google
        // already verified ownership of this address before ever issuing the email claim, so
        // there's nothing left for this project's own ConfirmEmail flow to add.
        var newUser = new ApplicationUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = true,
            FirstName = info.Principal.FindFirstValue(ClaimTypes.GivenName) ?? string.Empty,
            LastName = info.Principal.FindFirstValue(ClaimTypes.Surname) ?? string.Empty,
        };

        var createResult = await _userManager.CreateAsync(newUser);
        createResult.ThrowIfFailed("External account creation");

        var roleResult = await _userManager.AddToRoleAsync(newUser, DefaultRoleName);
        if (!roleResult.Succeeded)
        {
            // Mirrors AuthService.RegisterAsync's own rollback: without this, a transient
            // role-assignment failure would leave a permanent, roleless account behind with no
            // password to ever sign in with directly and no way to retry Google sign-in for this
            // email again (CreateAsync would now see it as a duplicate).
            await _userManager.DeleteAsync(newUser);
            roleResult.ThrowIfFailed("Default role assignment");
        }

        await _auditService.LogAsync("AssignRole", "User", newUser.Id.ToString(), new { Role = DefaultRoleName }, cancellationToken);

        var linkResult = await _userManager.AddLoginAsync(newUser, info);
        linkResult.ThrowIfFailed("Linking external login");

        return await _tokenService.IssueTokensAsync(newUser, cancellationToken);
    }
}
