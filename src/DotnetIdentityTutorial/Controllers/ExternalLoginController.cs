using DotnetIdentityTutorial.Dtos.Auth;
using DotnetIdentityTutorial.Exceptions;
using DotnetIdentityTutorial.Services.Interfaces;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Mvc;

namespace DotnetIdentityTutorial.Controllers;

/// <summary>
/// Sign in with Google, linked to an existing or newly created <c>ApplicationUser</c>. Every
/// action delegates to <see cref="IExternalLoginService"/> - this controller never calls
/// <c>SignInManager</c>/<c>UserManager</c> directly. Both actions are public: the OAuth round
/// trip itself is what proves identity here, there is no bearer token to check yet.
/// </summary>
[ApiController]
[Route("api/v1/[controller]")]
public sealed class ExternalLoginController : ControllerBase
{
    private readonly IExternalLoginService _externalLoginService;

    public ExternalLoginController(IExternalLoginService externalLoginService)
    {
        _externalLoginService = externalLoginService;
    }

    /// <summary>
    /// Initiates the OAuth challenge and redirects the browser to Google. <see cref="Challenge"/>
    /// is <see cref="ControllerBase"/>'s own built-in method - framework infrastructure, not an
    /// Identity manager call, so it's fine to invoke directly from a controller. The scheme name
    /// is passed explicitly: this project's <c>AddAuthentication(...).AddJwtBearer(...)</c>
    /// registration sets <c>DefaultChallengeScheme</c> to JWT Bearer, so relying on the default
    /// here would resolve to a 401 instead of the actual Google redirect.
    /// </summary>
    [HttpGet("Google")]
    public IActionResult Google()
    {
        var redirectUrl = Url.Action(nameof(GoogleCallback), "ExternalLogin", null, Request.Scheme)
            ?? throw new BusinessRuleException("Unable to build the external login callback URL.");

        var properties = _externalLoginService.BuildChallengeProperties(redirectUrl);
        return Challenge(properties, GoogleDefaults.AuthenticationScheme);
    }

    /// <summary>
    /// Handles Google's callback: resolves the external-login information off the ambient
    /// temp cookie <see cref="Google"/>'s challenge left behind, links or creates the
    /// <c>ApplicationUser</c> it corresponds to, and returns a real access + refresh token pair -
    /// the exact same shape and pipeline a password login returns.
    /// </summary>
    [HttpGet("Google/Callback")]
    public async Task<ActionResult<TokenResponse>> GoogleCallback(CancellationToken cancellationToken)
    {
        var info = await _externalLoginService.GetExternalLoginInfoAsync()
            ?? throw new BusinessRuleException("External login information was not found.");

        var tokens = await _externalLoginService.HandleExternalLoginCallbackAsync(info, cancellationToken);
        return Ok(tokens);
    }
}
