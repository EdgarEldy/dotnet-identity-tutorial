using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using DotnetIdentityTutorial.Authorization;
using DotnetIdentityTutorial.Dtos.Auth;
using DotnetIdentityTutorial.Dtos.User;
using DotnetIdentityTutorial.Exceptions;
using DotnetIdentityTutorial.RateLimiting;
using DotnetIdentityTutorial.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace DotnetIdentityTutorial.Controllers;

/// <summary>
/// The account lifecycle: registration, email confirmation, login, refresh, forgot/reset
/// password, change password, logout, and the current-user profile. Every action delegates to
/// <see cref="IAuthService"/> - this controller never calls <c>UserManager</c>/
/// <c>SignInManager</c>/<c>ITokenService</c> directly.
/// </summary>
[ApiController]
[Route("api/v1/[controller]")]
public sealed class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    /// <summary>
    /// 202 Accepted rather than 201 Created: registration doesn't hand back a usable resource
    /// yet (the account can't sign in until <see cref="ConfirmEmail"/> succeeds), so there is no
    /// meaningful <c>Location</c> to point a caller at. The response body is empty; the caller's
    /// next step is the confirmation link that was emailed, not a resource this endpoint returns.
    /// </summary>
    [HttpPost("Register")]
    [EnableRateLimiting(RateLimiterPolicies.Auth)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request, CancellationToken cancellationToken)
    {
        await _authService.RegisterAsync(request, cancellationToken);
        return Accepted();
    }

    /// <summary>
    /// Binds from the query string, not a JSON body - a confirmation link has to work from a
    /// plain browser navigation, e.g.
    /// <c>GET /api/v1/Auth/ConfirmEmail?userId=1&amp;token=...</c>.
    /// </summary>
    [HttpGet("ConfirmEmail")]
    public async Task<IActionResult> ConfirmEmail([FromQuery] ConfirmEmailRequest request, CancellationToken cancellationToken)
    {
        await _authService.ConfirmEmailAsync(request.UserId, request.Token, cancellationToken);
        return NoContent();
    }

    [HttpPost("Login")]
    [EnableRateLimiting(RateLimiterPolicies.Auth)]
    public async Task<ActionResult<TokenResponse>> Login([FromBody] LoginRequest request, CancellationToken cancellationToken)
    {
        var tokens = await _authService.LoginAsync(request, cancellationToken);
        return Ok(tokens);
    }

    [HttpPost("Refresh")]
    public async Task<ActionResult<TokenResponse>> Refresh([FromBody] RefreshRequest request, CancellationToken cancellationToken)
    {
        var tokens = await _authService.RefreshAsync(request, cancellationToken);
        return Ok(tokens);
    }

    /// <summary>
    /// Always 204 No Content, regardless of whether the submitted email matches an account - see
    /// <c>AuthService.ForgotPasswordAsync</c>'s own remarks for why this must never be
    /// special-cased.
    /// </summary>
    [HttpPost("ForgotPassword")]
    [EnableRateLimiting(RateLimiterPolicies.Auth)]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request, CancellationToken cancellationToken)
    {
        await _authService.ForgotPasswordAsync(request, cancellationToken);
        return NoContent();
    }

    [HttpPost("ResetPassword")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request, CancellationToken cancellationToken)
    {
        await _authService.ResetPasswordAsync(request, cancellationToken);
        return NoContent();
    }

    [HttpPost("ChangePassword")]
    [Authorize]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request, CancellationToken cancellationToken)
    {
        await _authService.ChangePasswordAsync(GetCurrentUserId(), request, cancellationToken);
        return NoContent();
    }

    [HttpPost("Logout")]
    [Authorize]
    public async Task<IActionResult> Logout(CancellationToken cancellationToken)
    {
        var jti = User.FindFirstValue(JwtRegisteredClaimNames.Jti)
            ?? throw new BusinessRuleException("The current access token is missing a jti claim.");
        var expiresAt = GetCurrentAccessTokenExpiry();

        await _authService.LogoutAsync(GetCurrentUserId(), jti, expiresAt, cancellationToken);
        return NoContent();
    }

    [HttpGet("Me")]
    [Authorize]
    public async Task<ActionResult<CurrentUserResponse>> Me(CancellationToken cancellationToken)
    {
        var profile = await _authService.GetMeAsync(GetCurrentUserId(), cancellationToken);

        // Permissions are read straight from the caller's own JWT "permission" claims - already
        // resolved once at sign-in by ApplicationUserClaimsPrincipalFactory - rather than
        // re-querying the database for them, that's the whole point of baking them into the
        // token.
        var permissions = User.FindAll(PermissionRequirement.ClaimType)
            .Select(c => c.Value)
            .Distinct()
            .ToList();

        return Ok(profile with { Permissions = permissions });
    }

    private int GetCurrentUserId()
    {
        var subject = User.FindFirstValue(JwtRegisteredClaimNames.Sub) ?? User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (subject is null || !int.TryParse(subject, out var userId))
        {
            throw new BusinessRuleException("The current access token is missing a valid subject claim.");
        }

        return userId;
    }

    private DateTimeOffset GetCurrentAccessTokenExpiry()
    {
        var exp = User.FindFirstValue(JwtRegisteredClaimNames.Exp);
        if (exp is null || !long.TryParse(exp, out var expUnixSeconds))
        {
            throw new BusinessRuleException("The current access token is missing an exp claim.");
        }

        return DateTimeOffset.FromUnixTimeSeconds(expUnixSeconds);
    }
}
