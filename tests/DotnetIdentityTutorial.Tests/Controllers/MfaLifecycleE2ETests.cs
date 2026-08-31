using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using DotnetIdentityTutorial.Dtos.Auth;
using DotnetIdentityTutorial.Tests.TestInfrastructure;

namespace DotnetIdentityTutorial.Tests.Controllers;

/// <summary>
/// The end-to-end coverage this branch's own README checklist asks for: "enabling 2FA, a login
/// attempt correctly stopping short of issuing tokens, completing it with a valid code, rejecting
/// an invalid one, and recovery-code login consuming a code so it can't be reused" - all driven
/// through <see cref="AuthWebApplicationFactory"/>'s real HTTP pipeline (JWT Bearer auth, the
/// "auth" rate limiter, everything), the same proof style as <c>AuthLifecycleE2ETests</c>.
///
/// Every <c>[Fact]</c> below constructs its own <see cref="AuthWebApplicationFactory"/> instance
/// rather than sharing one via <c>IClassFixture&lt;T&gt;</c> - the same reasoning
/// <c>AuthLifecycleE2ETests.Register_WithAnAlreadyRegisteredEmail_StillReturnsAccepted</c> already
/// applies to its own second test. Each scenario below needs its own account and up to 3 calls
/// against endpoints guarded by the shared "auth" rate limiter (Register, Login, VerifyTwoFactor -
/// see each Fact's own comments for the exact count), and the limiter partitions by client IP,
/// shared across every request one app instance handles regardless of which test method or
/// account made it. A fresh factory per Fact gives each scenario its own full 5-requests/minute
/// budget instead of them all silently competing for one shared budget the way they would under
/// one <c>IClassFixture&lt;T&gt;</c>-shared factory, without needing to disable the limiter the
/// way <c>AuthAccountLockoutE2ETests</c> does for its own, much larger, call count.
/// </summary>
public sealed class MfaLifecycleE2ETests
{
    private const string Password = "Passw0rd1";

    [Fact]
    public async Task Enable2fa_ThenConfirmWithAValidCode_ActivatesTwoFactorAndReturnsTenRecoveryCodes()
    {
        // Rate-limited calls used: Register (1), Login (2), Login (3) = 3 of 5.
        await using var factory = new AuthWebApplicationFactory();
        await factory.InitializeAsync();
        var client = factory.CreateClient();
        var email = $"{Guid.NewGuid():N}@example.com";

        var tokens = await AuthTestHelpers.RegisterConfirmAndLoginAsync(client, factory.EmailService, email, Password);

        var enableResponse = await SendAuthenticatedAsync(client, tokens.AccessToken, "Auth/Enable2fa");
        Assert.Equal(HttpStatusCode.OK, enableResponse.StatusCode);

        var enable = await enableResponse.Content.ReadFromJsonAsync<Enable2faResponse>(AuthTestHelpers.JsonOptions);
        Assert.NotNull(enable);
        Assert.False(string.IsNullOrWhiteSpace(enable!.SharedKey));
        Assert.StartsWith("otpauth://totp/", enable.AuthenticatorUri);

        var code = TotpTestHelper.ComputeCurrentCode(enable.SharedKey);
        var confirmResponse = await client.PostAsJsonAsync(
            "/api/v1/Auth/Confirm2fa", new { Code = code }, AuthTestHelpers.JsonOptions);
        Assert.Equal(HttpStatusCode.OK, confirmResponse.StatusCode);

        var confirm = await confirmResponse.Content.ReadFromJsonAsync<Confirm2faResponse>(AuthTestHelpers.JsonOptions);
        Assert.NotNull(confirm);
        Assert.Equal(10, confirm!.RecoveryCodes.Count);
        Assert.All(confirm.RecoveryCodes, recoveryCode => Assert.False(string.IsNullOrWhiteSpace(recoveryCode)));

        // There is no direct "read the user's TwoFactorEnabled flag" endpoint - a fresh Login
        // attempt is the observable proof Confirm2fa actually flipped it: before this point, the
        // very same credentials logged in directly (see RegisterConfirmAndLoginAsync above); now
        // they must stop short of issuing tokens instead.
        var loginAfterEnabling = await client.PostAsJsonAsync(
            "/api/v1/Auth/Login", new { Email = email, Password }, AuthTestHelpers.JsonOptions);
        Assert.Equal(HttpStatusCode.Accepted, loginAfterEnabling.StatusCode);
    }

    [Fact]
    public async Task Login_WithTwoFactorEnabled_StopsShortOfIssuingTokens_ThenVerifyTwoFactorRejectsAnInvalidCodeAndAcceptsAValidOne()
    {
        // Rate-limited calls used: Register (1), Login (2), Login (3), VerifyTwoFactor invalid (4),
        // VerifyTwoFactor valid (5) = 5 of 5.
        await using var factory = new AuthWebApplicationFactory();
        await factory.InitializeAsync();
        var client = factory.CreateClient();
        var email = $"{Guid.NewGuid():N}@example.com";

        var initialTokens = await AuthTestHelpers.RegisterConfirmAndLoginAsync(client, factory.EmailService, email, Password);
        var (sharedKey, _) = await AuthTestHelpers.EnableAndConfirmTwoFactorAsync(client, initialTokens.AccessToken);

        // Clear the bearer header Enable2fa/Confirm2fa left behind - Login itself is public and
        // must not require it.
        client.DefaultRequestHeaders.Authorization = null;

        var loginResponse = await client.PostAsJsonAsync(
            "/api/v1/Auth/Login", new { Email = email, Password }, AuthTestHelpers.JsonOptions);
        Assert.Equal(HttpStatusCode.Accepted, loginResponse.StatusCode);

        // Explicitly prove the 202 body carries no usable token pair, not just that it happens to
        // deserialize into TwoFactorRequiredResponse - read the raw JSON and assert neither an
        // "accessToken" nor a "refreshToken" property is present anywhere in it.
        var rawBody = await loginResponse.Content.ReadAsStringAsync();
        using (var document = JsonDocument.Parse(rawBody))
        {
            Assert.False(document.RootElement.TryGetProperty("accessToken", out _));
            Assert.False(document.RootElement.TryGetProperty("refreshToken", out _));
        }

        var challenge = JsonSerializer.Deserialize<TwoFactorRequiredResponse>(rawBody, AuthTestHelpers.JsonOptions);
        Assert.NotNull(challenge);
        Assert.False(string.IsNullOrWhiteSpace(challenge!.TwoFactorToken));

        // Rejecting an invalid code: garbage that can never match a real TOTP/recovery code.
        var invalidVerifyResponse = await client.PostAsJsonAsync(
            "/api/v1/Auth/VerifyTwoFactor",
            new { TwoFactorToken = challenge.TwoFactorToken, Code = "000000" },
            AuthTestHelpers.JsonOptions);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, invalidVerifyResponse.StatusCode);

        // Completing with a valid code: the challenge token from the 202 above is a stateless JWT
        // (not a one-time database row), so it is still valid here - only the TOTP/recovery code
        // itself is checked per attempt.
        var validCode = TotpTestHelper.ComputeCurrentCode(sharedKey);
        var validVerifyResponse = await client.PostAsJsonAsync(
            "/api/v1/Auth/VerifyTwoFactor",
            new { TwoFactorToken = challenge.TwoFactorToken, Code = validCode },
            AuthTestHelpers.JsonOptions);
        Assert.Equal(HttpStatusCode.OK, validVerifyResponse.StatusCode);

        var tokens = await validVerifyResponse.Content.ReadFromJsonAsync<TokenResponse>(AuthTestHelpers.JsonOptions);
        Assert.NotNull(tokens);
        Assert.False(string.IsNullOrWhiteSpace(tokens!.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(tokens.RefreshToken));

        // The issued access token is a real, usable one - proven against a protected endpoint,
        // the same pattern AuthLifecycleE2ETests uses for its own plain-login tokens.
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        var meResponse = await client.GetAsync("/api/v1/Auth/Me");
        Assert.Equal(HttpStatusCode.OK, meResponse.StatusCode);
    }

    [Fact]
    public async Task VerifyTwoFactor_WithARecoveryCode_IssuesTokensThenRejectsTheSameCodeOnASecondAttempt()
    {
        // Rate-limited calls used: Register (1), Login (2), Login (3), VerifyTwoFactor recovery
        // #1 (4), VerifyTwoFactor recovery #1 reused (5) = 5 of 5.
        await using var factory = new AuthWebApplicationFactory();
        await factory.InitializeAsync();
        var client = factory.CreateClient();
        var email = $"{Guid.NewGuid():N}@example.com";

        var initialTokens = await AuthTestHelpers.RegisterConfirmAndLoginAsync(client, factory.EmailService, email, Password);
        var (_, recoveryCodes) = await AuthTestHelpers.EnableAndConfirmTwoFactorAsync(client, initialTokens.AccessToken);
        var recoveryCode = recoveryCodes[0];

        client.DefaultRequestHeaders.Authorization = null;

        var loginResponse = await client.PostAsJsonAsync(
            "/api/v1/Auth/Login", new { Email = email, Password }, AuthTestHelpers.JsonOptions);
        Assert.Equal(HttpStatusCode.Accepted, loginResponse.StatusCode);
        var challenge = await loginResponse.Content.ReadFromJsonAsync<TwoFactorRequiredResponse>(AuthTestHelpers.JsonOptions);
        Assert.NotNull(challenge);

        // AuthService.VerifyTwoFactorAsync tries the submitted code as a TOTP code first, then
        // falls back to UserManager.RedeemTwoFactorRecoveryCodeAsync - a recovery code is never a
        // valid 6-digit TOTP code by construction, so this exercises the fallback path.
        var firstAttempt = await client.PostAsJsonAsync(
            "/api/v1/Auth/VerifyTwoFactor",
            new { TwoFactorToken = challenge!.TwoFactorToken, Code = recoveryCode },
            AuthTestHelpers.JsonOptions);
        Assert.Equal(HttpStatusCode.OK, firstAttempt.StatusCode);

        var tokens = await firstAttempt.Content.ReadFromJsonAsync<TokenResponse>(AuthTestHelpers.JsonOptions);
        Assert.NotNull(tokens);
        Assert.False(string.IsNullOrWhiteSpace(tokens!.AccessToken));

        // Redeeming the exact same recovery code again must fail - RedeemTwoFactorRecoveryCodeAsync's
        // own one-time-use semantics, the "so it can't be reused" half of the README's checklist
        // wording. The challenge token itself is still valid (stateless, not consumed by the first
        // attempt), so a second rejection here can only be explained by the recovery code itself
        // having already been spent.
        var secondAttempt = await client.PostAsJsonAsync(
            "/api/v1/Auth/VerifyTwoFactor",
            new { TwoFactorToken = challenge.TwoFactorToken, Code = recoveryCode },
            AuthTestHelpers.JsonOptions);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, secondAttempt.StatusCode);
    }

    [Fact]
    public async Task Disable2fa_ThenLogin_ReturnsRealTokensDirectlyInsteadOfATwoFactorChallenge()
    {
        // Rate-limited calls used: Register (1), Login (2), Login (3) = 3 of 5.
        await using var factory = new AuthWebApplicationFactory();
        await factory.InitializeAsync();
        var client = factory.CreateClient();
        var email = $"{Guid.NewGuid():N}@example.com";

        var initialTokens = await AuthTestHelpers.RegisterConfirmAndLoginAsync(client, factory.EmailService, email, Password);
        await AuthTestHelpers.EnableAndConfirmTwoFactorAsync(client, initialTokens.AccessToken);

        // Disable2fa reuses the still-valid access token EnableAndConfirmTwoFactorAsync left on
        // the client's default headers - 2FA being enabled doesn't itself invalidate the access
        // token that was issued before it was turned on.
        var disableResponse = await client.PostAsync("/api/v1/Auth/Disable2fa", content: null);
        Assert.Equal(HttpStatusCode.NoContent, disableResponse.StatusCode);

        client.DefaultRequestHeaders.Authorization = null;

        var loginAfterDisabling = await client.PostAsJsonAsync(
            "/api/v1/Auth/Login", new { Email = email, Password }, AuthTestHelpers.JsonOptions);
        Assert.Equal(HttpStatusCode.OK, loginAfterDisabling.StatusCode);

        var tokens = await loginAfterDisabling.Content.ReadFromJsonAsync<TokenResponse>(AuthTestHelpers.JsonOptions);
        Assert.NotNull(tokens);
        Assert.False(string.IsNullOrWhiteSpace(tokens!.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(tokens.RefreshToken));
    }

    private static Task<HttpResponseMessage> SendAuthenticatedAsync(HttpClient client, string accessToken, string relativeUrl)
    {
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return client.PostAsync($"/api/v1/{relativeUrl}", content: null);
    }
}
