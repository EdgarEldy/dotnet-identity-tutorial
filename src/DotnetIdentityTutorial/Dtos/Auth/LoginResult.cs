namespace DotnetIdentityTutorial.Dtos.Auth;

/// <summary>
/// The outcome of <c>IAuthService.LoginAsync</c>. Exactly one of the two properties is set:
/// <see cref="Tokens"/> for a plain login that issued a full access/refresh token pair
/// directly, <see cref="TwoFactorToken"/> when the account has 2FA enabled and the login must
/// stop short of issuing real tokens until <c>VerifyTwoFactorAsync</c> completes it with a valid
/// TOTP/recovery code. <see cref="RequiresTwoFactor"/> is a computed convenience for the
/// controller rather than a third independent flag that could disagree with the other two.
/// </summary>
public sealed record LoginResult(TokenResponse? Tokens, string? TwoFactorToken)
{
    public bool RequiresTwoFactor => TwoFactorToken is not null;
}
