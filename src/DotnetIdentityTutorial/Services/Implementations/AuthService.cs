using DotnetIdentityTutorial.Dtos.Auth;
using DotnetIdentityTutorial.Dtos.User;
using DotnetIdentityTutorial.Exceptions;
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
    /// design; nobody can self-register into <c>ADMIN</c> through this endpoint.
    /// </summary>
    private const string DefaultRoleName = "USER";

    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ITokenService _tokenService;
    private readonly IEmailService _emailService;
    private readonly IConfiguration _configuration;

    public AuthService(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ITokenService tokenService,
        IEmailService emailService,
        IConfiguration configuration)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _tokenService = tokenService;
        _emailService = emailService;
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
            var errors = string.Join(", ", createResult.Errors.Select(e => e.Description));
            throw new BusinessRuleException($"Registration failed: {errors}");
        }

        var roleResult = await _userManager.AddToRoleAsync(user, DefaultRoleName);
        if (!roleResult.Succeeded)
        {
            var errors = string.Join(", ", roleResult.Errors.Select(e => e.Description));
            throw new BusinessRuleException($"Failed to assign the default role: {errors}");
        }

        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var confirmationLink = BuildLink("Auth/ConfirmEmail", ("userId", user.Id.ToString()), ("token", token));

        await _emailService.SendConfirmationEmailAsync(user.Email!, confirmationLink);
    }

    public async Task ConfirmEmailAsync(int userId, string token, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString())
            ?? throw new ResourceNotFoundException($"User {userId} was not found.");

        var result = await _userManager.ConfirmEmailAsync(user, token);
        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            throw new BusinessRuleException($"Email confirmation failed: {errors}");
        }
    }

    public async Task<TokenResponse> LoginAsync(LoginRequest request, CancellationToken cancellationToken = default)
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
        // EmailConfirmed itself. No 2FA branch here yet: LoginAsync always issues tokens
        // directly on success, per feature/mfa's own note that it - not this branch - is what
        // introduces the "2FA required" partial result.
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
            var resetLink = BuildLink("Auth/ResetPassword", ("email", user.Email!), ("token", token));
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
        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            throw new BusinessRuleException($"Password reset failed: {errors}");
        }
    }

    public async Task ChangePasswordAsync(int userId, ChangePasswordRequest request, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString())
            ?? throw new ResourceNotFoundException($"User {userId} was not found.");

        // Same automatic SecurityStamp rotation as ResetPasswordAsync above - ChangePasswordAsync
        // goes through the same internal UpdatePasswordHash path in UserManager.
        var result = await _userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            throw new BusinessRuleException($"Password change failed: {errors}");
        }
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
        return $"{baseUrl}/api/v1/{relativePath}?{query}";
    }
}
