using DotnetIdentityTutorial.Dtos.Auth;
using DotnetIdentityTutorial.Dtos.User;
using DotnetIdentityTutorial.Exceptions;
using DotnetIdentityTutorial.Extensions;
using DotnetIdentityTutorial.Identity;
using DotnetIdentityTutorial.Services.Interfaces;
using Microsoft.AspNetCore.Identity;

namespace DotnetIdentityTutorial.Services.Implementations;

/// <summary>
/// The one place allowed to call <see cref="UserManager{TUser}"/>/<see cref="SignInManager{TUser}"/>
/// for the account lifecycle - see <see cref="IAuthService"/>'s own remarks. Token issuance,
/// rotation, and revocation are delegated to <see cref="ITokenService"/> throughout; this class
/// never builds a JWT or touches <c>RefreshToken</c>/<c>BlacklistedAccessToken</c> directly.
/// </summary>
public sealed class AuthService : IAuthService
{
    /// <summary>
    /// The role every self-registered account gets - matches the seeded role name in
    /// <c>Data/DbInitializer</c>. Only <c>ADMIN</c> grants extra permissions beyond this by
    /// design; nobody can self-register into <c>ADMIN</c> through this endpoint. Internal rather
    /// than private: <see cref="ExternalLoginService"/> assigns the exact same default role to a
    /// brand-new Google-created account, and a single source of truth means the two account-
    /// creation paths can't silently drift apart if this name ever changes.
    /// </summary>
    internal const string DefaultRoleName = "USER";

    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ITokenService _tokenService;
    private readonly IEmailService _emailService;
    private readonly IAuditService _auditService;
    private readonly IConfiguration _configuration;

    public AuthService(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ITokenService tokenService,
        IEmailService emailService,
        IAuditService auditService,
        IConfiguration configuration)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _tokenService = tokenService;
        _emailService = emailService;
        _auditService = auditService;
        _configuration = configuration;
    }

    public async Task RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default)
    {
        var user = new ApplicationUser
        {
            UserName = request.Email,
            Email = request.Email,
            FirstName = request.FirstName,
            LastName = request.LastName,
        };

        var createResult = await _userManager.CreateAsync(user, request.Password);
        if (!createResult.Succeeded)
        {
            if (IsDuplicateAccountError(createResult))
            {
                // Same outcome as a fresh registration (the controller returns 202 Accepted
                // either way, no exception thrown): a distinguishable response for "this email
                // is already taken" would make Register a user-enumeration oracle, the same
                // problem ForgotPasswordAsync's own identical-response rule exists to prevent -
                // LoginAsync above already generalizes that reasoning past ForgotPassword alone.
                return;
            }

            createResult.ThrowIfFailed("Registration");
        }

        var roleResult = await _userManager.AddToRoleAsync(user, DefaultRoleName);
        if (!roleResult.Succeeded)
        {
            // CreateAsync already committed the user row; without this compensating delete a
            // transient role-assignment failure would leave a permanent, roleless, unconfirmed
            // account with no confirmation email ever sent and no way to retry registration for
            // that email again.
            await _userManager.DeleteAsync(user);
            roleResult.ThrowIfFailed("Default role assignment");
        }

        await _auditService.LogAsync("AssignRole", "User", user.Id.ToString(), new { Role = DefaultRoleName }, cancellationToken);

        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var confirmationLink = BuildApiLink("Auth/ConfirmEmail", ("userId", user.Id.ToString()), ("token", token));

        await _emailService.SendConfirmationEmailAsync(user.Email!, confirmationLink);
    }

    public async Task ConfirmEmailAsync(int userId, string token, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString())
            ?? throw new ResourceNotFoundException($"User {userId} was not found.");

        var result = await _userManager.ConfirmEmailAsync(user, token);
        result.ThrowIfFailed("Email confirmation");
    }

    public async Task<LoginResult> LoginAsync(LoginRequest request, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null)
        {
            // Same generic message as a wrong password below - distinguishing "no such account"
            // here would make Login itself a user-enumeration oracle, the exact problem
            // ForgotPasswordAsync's own identical-response rule exists to prevent.
            throw new BusinessRuleException("Invalid email or password.");
        }

        // CheckPasswordSignInAsync (not just VerifyPasswordAsync) is what correctly integrates
        // with Identity's own lockout counting - a failed attempt increments AccessFailedCount
        // and locks the account after Lockout.MaxFailedAccessAttempts - and its IsNotAllowed
        // result already reflects RequireConfirmedAccount without this method re-checking
        // EmailConfirmed itself.
        //
        // Deliberately CheckPasswordSignInAsync, not the higher-level PasswordSignInAsync:
        // PasswordSignInAsync is the one that inspects TwoFactorEnabled and returns
        // SignInResult.TwoFactorRequired (via its own internal SignInOrTwoFactorAsync), but it
        // does so by also establishing Identity's own cookie-based sign-in ticket
        // (HttpContext.SignInAsync against the cookie scheme AddIdentity registers) as a side
        // effect of a successful check - a side effect with no place in this stateless JWT API.
        // CheckPasswordSignInAsync never sets RequiresTwoFactor at all (confirmed by reading the
        // installed SignInManager's own implementation, not assumed): it only verifies the
        // password and applies lockout counting, deliberately stopping short of cookie issuance
        // or 2FA gating. 2FA therefore has to be checked explicitly below, once the password
        // itself is confirmed correct, via the same SignInManager.IsTwoFactorEnabledAsync check
        // PasswordSignInAsync uses internally - not by reading result.RequiresTwoFactor, which
        // this call path never sets.
        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);

        if (result.IsLockedOut)
        {
            throw new BusinessRuleException("This account is locked out. Try again later.");
        }

        if (result.IsNotAllowed)
        {
            throw new BusinessRuleException("This account is not allowed to sign in yet. Confirm your email first.");
        }

        if (!result.Succeeded)
        {
            throw new BusinessRuleException("Invalid email or password.");
        }

        if (await _signInManager.IsTwoFactorEnabledAsync(user))
        {
            // The password check already succeeded at this point - what's missing is the second
            // factor, not proof of identity itself. Stop short of issuing real tokens: instead
            // hand back a short-lived challenge token (the "partial login ticket") that only
            // VerifyTwoFactorAsync can exchange for a real token pair, and only after a valid
            // TOTP/recovery code. See ITokenService.IssueTwoFactorChallengeTokenAsync's own
            // remarks for why a signed JWT with a different audience - not Identity's own
            // two-factor cookie - is what makes this safe in a stateless API.
            var twoFactorToken = await _tokenService.IssueTwoFactorChallengeTokenAsync(user, cancellationToken);
            return new LoginResult(null, twoFactorToken);
        }

        var tokens = await _tokenService.IssueTokensAsync(user, cancellationToken);
        return new LoginResult(tokens, null);
    }

    public async Task<TokenResponse> VerifyTwoFactorAsync(VerifyTwoFactorRequest request, CancellationToken cancellationToken = default)
    {
        var userId = await _tokenService.ValidateTwoFactorChallengeTokenAsync(request.TwoFactorToken, cancellationToken);

        var user = await _userManager.FindByIdAsync(userId.ToString())
            ?? throw new ResourceNotFoundException($"User {userId} was not found.");

        // LoginAsync's own lockout check happens once, at the password step - but the challenge
        // token can be presented up to TokenService's own 5-minute window later, long enough for
        // an admin to lock the account (UserAdminService.LockUserAsync) in between. Without this,
        // a lock applied mid-flow would have no effect on a login already past its password step.
        if (await _userManager.IsLockedOutAsync(user))
        {
            throw new BusinessRuleException("This account is locked out. Try again later.");
        }

        // Tries a TOTP code first, then falls back to a recovery code - never revealing to the
        // caller which of the two was attempted, only whether the overall attempt succeeded.
        // Distinguishing the two failure modes would tell an attacker something about the shape
        // of the code they submitted, the same anti-enumeration reasoning LoginAsync's own
        // generic "Invalid email or password" already follows.
        var isValidTotp = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, request.Code);
        if (!isValidTotp)
        {
            var recoveryResult = await _userManager.RedeemTwoFactorRecoveryCodeAsync(user, request.Code);
            if (!recoveryResult.Succeeded)
            {
                // Shares Identity's own lockout counter with a wrong password (CheckPasswordSignInAsync
                // already does this for Login) - a 6-digit TOTP code guarding an already-password-
                // verified session still needs its own brute-force accounting, not just the "auth"
                // rate limiter's shared-across-clients budget, or repeated guesses against one
                // account would go uncounted past the rate limiter's own window.
                await _userManager.AccessFailedAsync(user);
                throw new BusinessRuleException("Invalid two-factor code.");
            }
        }

        await _userManager.ResetAccessFailedCountAsync(user);
        return await _tokenService.IssueTokensAsync(user, cancellationToken);
    }

    public Task<TokenResponse> RefreshAsync(RefreshRequest request, CancellationToken cancellationToken = default)
    {
        return _tokenService.RefreshAsync(request.RefreshToken, cancellationToken);
    }

    public async Task ForgotPasswordAsync(ForgotPasswordRequest request, CancellationToken cancellationToken = default)
    {
        // No early return on either branch below: this method must take roughly the same amount
        // of time and always end the same way (the controller returns 204 No Content
        // unconditionally) whether or not request.Email matches an account - a distinguishable
        // response, or a measurably faster one, would turn this endpoint into a user-enumeration
        // oracle. See the README's "ForgotPassword" rule.
        var user = await _userManager.FindByEmailAsync(request.Email);

        if (user is not null)
        {
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            // Unlike the ConfirmEmail link, this can't point at the API's own POST endpoint - a
            // browser navigating to a link only ever issues a GET, and resetting a password
            // needs a form to collect the new password anyway. This targets a frontend route
            // (no "/api/v1" prefix) that would collect the new password and then call
            // POST /api/v1/Auth/ResetPassword itself; this tutorial has no frontend to host that
            // route, so EmailService just logs the link instead of it being clickable end to end.
            var resetLink = BuildFrontendLink("reset-password", ("email", user.Email!), ("token", token));
            await _emailService.SendPasswordResetEmailAsync(user.Email!, resetLink);
        }
        else
        {
            // No account matches - do an equivalent amount of cryptographic work anyway instead
            // of returning immediately, so the response timing doesn't leak which branch ran.
            // PasswordHasher<TUser>'s default implementation never actually reads the user
            // argument, so passing null here is safe and this costs comparable time to
            // GeneratePasswordResetTokenAsync's own token-provider work above.
            _ = _userManager.PasswordHasher.HashPassword(null!, Guid.NewGuid().ToString());
        }
    }

    public async Task ResetPasswordAsync(ResetPasswordRequest request, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByEmailAsync(request.Email)
            ?? throw new ResourceNotFoundException("User was not found.");

        // Identity's own UserManager.ResetPasswordAsync rotates SecurityStamp internally as part
        // of setting the new password hash - that's what makes every outstanding refresh token
        // family reject at its SecurityStamp comparison in TokenService.RefreshAsync afterward.
        // Nothing extra is needed here for that invariant to hold.
        var result = await _userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);
        result.ThrowIfFailed("Password reset");
    }

    public async Task ChangePasswordAsync(int userId, ChangePasswordRequest request, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString())
            ?? throw new ResourceNotFoundException($"User {userId} was not found.");

        // Same automatic SecurityStamp rotation as ResetPasswordAsync above - ChangePasswordAsync
        // goes through the same internal UpdatePasswordHash path in UserManager.
        var result = await _userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
        result.ThrowIfFailed("Password change");
    }

    public Task LogoutAsync(int userId, string accessTokenJti, DateTimeOffset accessTokenExpiresAt, CancellationToken cancellationToken = default)
    {
        return _tokenService.RevokeAsync(accessTokenJti, userId, accessTokenExpiresAt, cancellationToken);
    }

    public async Task<CurrentUserResponse> GetMeAsync(int userId, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString())
            ?? throw new ResourceNotFoundException($"User {userId} was not found.");

        var roles = await _userManager.GetRolesAsync(user);

        // Permissions intentionally left empty here - the controller fills them in from the
        // caller's own JWT "permission" claims (already resolved once at sign-in by
        // ApplicationUserClaimsPrincipalFactory), not by re-querying the database for them.
        return new CurrentUserResponse(
            user.Id,
            user.Email ?? string.Empty,
            user.FirstName,
            user.LastName,
            roles.ToList(),
            []);
    }

    /// <summary>
    /// Builds a link at this API's own <c>/api/v1/...</c> route - only valid for a link meant to
    /// be navigated to directly, i.e. one bound by <c>[HttpGet]</c>/<c>[FromQuery]</c> on the
    /// receiving end, such as <c>ConfirmEmail</c>.
    /// </summary>
    private string BuildApiLink(string relativePath, params (string Key, string Value)[] queryParameters)
        => BuildLink($"api/v1/{relativePath}", queryParameters);

    /// <summary>
    /// Builds a link with no <c>/api/v1</c> prefix, for a route meant to be hosted by a frontend
    /// application rather than this API directly - see <see cref="ForgotPasswordAsync"/>'s own
    /// remarks on why <c>ResetPassword</c> needs this instead of <see cref="BuildApiLink"/>.
    /// </summary>
    private string BuildFrontendLink(string relativePath, params (string Key, string Value)[] queryParameters)
        => BuildLink(relativePath, queryParameters);

    /// <summary>
    /// Builds an absolute link against the configured <c>App:BaseUrl</c> (a placeholder base URL
    /// for this tutorial - see appsettings.json), URL-encoding every query value, most
    /// importantly the token itself, which can contain characters "+"/"/" that are not safe
    /// unescaped in a query string.
    /// </summary>
    private string BuildLink(string relativePath, params (string Key, string Value)[] queryParameters)
    {
        var baseUrl = _configuration["App:BaseUrl"]?.TrimEnd('/')
            ?? throw new InvalidOperationException("Missing 'App:BaseUrl' configuration value.");

        var query = string.Join("&", queryParameters.Select(p => $"{p.Key}={Uri.EscapeDataString(p.Value)}"));
        return $"{baseUrl}/{relativePath}?{query}";
    }

    /// <summary>
    /// A failed email/username collision is the only <see cref="IdentityResult"/> outcome that
    /// must never surface as a distinguishable error - see the enumeration-prevention remark in
    /// <see cref="RegisterAsync"/> above.
    /// </summary>
    private static bool IsDuplicateAccountError(IdentityResult result)
        => result.Errors.All(e => e.Code is "DuplicateUserName" or "DuplicateEmail");
}
