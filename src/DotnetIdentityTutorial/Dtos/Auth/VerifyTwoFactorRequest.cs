namespace DotnetIdentityTutorial.Dtos.Auth;

/// <summary>
/// The body of <c>POST /api/v1/Auth/VerifyTwoFactor</c>. <see cref="TwoFactorToken"/> is the
/// short-lived challenge token <see cref="TwoFactorRequiredResponse"/> handed back from Login -
/// the "partial login ticket" the README's endpoint table refers to, a signed JWT rather than
/// Identity's own two-factor cookie (see <c>Services/Implementations/TokenService</c>'s remarks
/// on <c>IssueTwoFactorChallengeTokenAsync</c> for why). <see cref="Code"/> is either a 6-digit
/// TOTP code or a recovery code - the endpoint tries both, see <c>AuthService.VerifyTwoFactorAsync</c>.
/// </summary>
public sealed record VerifyTwoFactorRequest(string TwoFactorToken, string Code);
