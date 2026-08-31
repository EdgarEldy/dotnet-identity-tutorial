using OtpNet;

namespace DotnetIdentityTutorial.Tests.TestInfrastructure;

/// <summary>
/// Computes a real, currently-valid 6-digit TOTP code from a raw base32 shared key - the same
/// value <c>AuthController.Enable2fa</c> hands back as <c>Enable2faResponse.SharedKey</c>. Both
/// <c>Confirm2fa</c> and completing a 2FA-gated login need an actual code that
/// <c>UserManager.VerifyTwoFactorTokenAsync</c> will accept at the moment the test sends it, not
/// a stub value - there is no way to drive that end to end without a real RFC 6238 implementation
/// somewhere in the test project.
///
/// Uses <c>Otp.NET</c> (MIT licensed, the standard .NET RFC 6238 implementation) rather than
/// hand-rolling the HMAC-based one-time-password algorithm here: Identity's own
/// <c>AuthenticatorTokenProvider</c> (resolved via <c>TokenOptions.DefaultAuthenticatorProvider</c>,
/// registered by <c>AddDefaultTokenProviders()</c> in <c>Program.cs</c>) uses exactly the defaults
/// this helper relies on unmodified - HMAC-SHA1, a 30-second time step, 6 digits - so a code
/// computed here is the same code a real authenticator app would display at the same moment, not
/// an approximation of one.
/// </summary>
internal static class TotpTestHelper
{
    public static string ComputeCurrentCode(string base32SharedKey)
    {
        var keyBytes = Base32Encoding.ToBytes(base32SharedKey);
        return new Totp(keyBytes).ComputeTotp();
    }
}
