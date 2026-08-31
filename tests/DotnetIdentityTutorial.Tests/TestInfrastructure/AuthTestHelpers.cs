using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using DotnetIdentityTutorial.Dtos.Auth;

namespace DotnetIdentityTutorial.Tests.TestInfrastructure;

/// <summary>
/// Shared register/confirm plumbing for the end-to-end <c>AuthController</c> tests, so the
/// lifecycle test and the lockout test (both of which need a real confirmed account before they
/// can exercise their own scenario) don't each re-implement the same HTTP calls and query-string
/// parsing.
/// </summary>
internal static class AuthTestHelpers
{
    /// <summary>
    /// <c>System.Net.Http.Json</c>'s default <see cref="JsonSerializerOptions"/> (matching
    /// plain <see cref="JsonSerializerOptions.Default"/>) is case-sensitive; ASP.NET Core's own
    /// controllers serialize with camelCase property names by default. Every request/response
    /// body in these tests is sent/read with this explicit "Web" default instead, so a PascalCase
    /// C# record still round-trips correctly against the camelCase JSON on the wire.
    /// </summary>
    public static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static async Task<(int UserId, string Token)> RegisterAsync(
        HttpClient client, FakeEmailService emailService, string email, string password)
    {
        var response = await client.PostAsJsonAsync(
            "/api/v1/Auth/Register",
            new { Email = email, Password = password, FirstName = "Ada", LastName = "Lovelace" },
            JsonOptions);

        if (response.StatusCode != HttpStatusCode.Accepted)
        {
            var body = await response.Content.ReadAsStringAsync();
            throw new InvalidOperationException($"Test setup failed: Register returned {response.StatusCode}: {body}");
        }

        var confirmationLink = emailService.LastConfirmationLink
            ?? throw new InvalidOperationException("Test setup failed: no confirmation link was captured by FakeEmailService.");

        var query = ParseLinkQuery(confirmationLink);
        return (int.Parse(query["userId"]), query["token"]);
    }

    public static async Task ConfirmEmailAsync(HttpClient client, int userId, string token)
    {
        var response = await client.GetAsync($"/api/v1/Auth/ConfirmEmail?userId={userId}&token={Uri.EscapeDataString(token)}");
        if (response.StatusCode != HttpStatusCode.NoContent)
        {
            var body = await response.Content.ReadAsStringAsync();
            throw new InvalidOperationException($"Test setup failed: ConfirmEmail returned {response.StatusCode}: {body}");
        }
    }

    public static async Task RegisterAndConfirmAsync(
        HttpClient client, FakeEmailService emailService, string email, string password)
    {
        var (userId, token) = await RegisterAsync(client, emailService, email, password);
        await ConfirmEmailAsync(client, userId, token);
    }

    /// <summary>
    /// Registers, confirms, and logs in a brand-new account with no 2FA enabled yet, returning
    /// the real token pair - the starting point every MFA end-to-end test needs before it can
    /// call the authenticated <c>Enable2fa</c>/<c>Confirm2fa</c>/<c>Disable2fa</c> actions. Counts
    /// as two calls against the shared "auth" rate limiter budget (Register, Login), which callers
    /// need to account for alongside their own additional Login/VerifyTwoFactor calls.
    /// </summary>
    public static async Task<TokenResponse> RegisterConfirmAndLoginAsync(
        HttpClient client, FakeEmailService emailService, string email, string password)
    {
        await RegisterAndConfirmAsync(client, emailService, email, password);

        var loginResponse = await client.PostAsJsonAsync(
            "/api/v1/Auth/Login", new { Email = email, Password = password }, JsonOptions);
        if (loginResponse.StatusCode != HttpStatusCode.OK)
        {
            var body = await loginResponse.Content.ReadAsStringAsync();
            throw new InvalidOperationException($"Test setup failed: Login returned {loginResponse.StatusCode}: {body}");
        }

        return await loginResponse.Content.ReadFromJsonAsync<TokenResponse>(JsonOptions)
            ?? throw new InvalidOperationException("Test setup failed: Login returned an empty body.");
    }

    /// <summary>
    /// Enables 2FA for the account identified by <paramref name="accessToken"/> and immediately
    /// confirms it with a real TOTP code computed (via <see cref="TotpTestHelper"/>) from the
    /// shared key <c>Enable2fa</c> hands back, activating 2FA and returning the one-time set of
    /// recovery codes <c>Confirm2fa</c> generates. Neither call is rate-limited (only
    /// Login/Register/ForgotPassword/VerifyTwoFactor carry <c>[EnableRateLimiting]</c>), so this
    /// doesn't count against a test's "auth" policy budget.
    /// </summary>
    public static async Task<(string SharedKey, IReadOnlyList<string> RecoveryCodes)> EnableAndConfirmTwoFactorAsync(
        HttpClient client, string accessToken)
    {
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        var enableResponse = await client.PostAsync("/api/v1/Auth/Enable2fa", content: null);
        if (enableResponse.StatusCode != HttpStatusCode.OK)
        {
            var body = await enableResponse.Content.ReadAsStringAsync();
            throw new InvalidOperationException($"Test setup failed: Enable2fa returned {enableResponse.StatusCode}: {body}");
        }

        var enable = await enableResponse.Content.ReadFromJsonAsync<Enable2faResponse>(JsonOptions)
            ?? throw new InvalidOperationException("Test setup failed: Enable2fa returned an empty body.");

        var code = TotpTestHelper.ComputeCurrentCode(enable.SharedKey);
        var confirmResponse = await client.PostAsJsonAsync("/api/v1/Auth/Confirm2fa", new { Code = code }, JsonOptions);
        if (confirmResponse.StatusCode != HttpStatusCode.OK)
        {
            var body = await confirmResponse.Content.ReadAsStringAsync();
            throw new InvalidOperationException($"Test setup failed: Confirm2fa returned {confirmResponse.StatusCode}: {body}");
        }

        var confirm = await confirmResponse.Content.ReadFromJsonAsync<Confirm2faResponse>(JsonOptions)
            ?? throw new InvalidOperationException("Test setup failed: Confirm2fa returned an empty body.");

        return (enable.SharedKey, confirm.RecoveryCodes);
    }

    /// <summary>
    /// Parses the query string off a link built by <c>AuthService.BuildLink</c> (e.g.
    /// <c>.../ConfirmEmail?userId=1&amp;token=abc</c>) into a lookup by key, undoing the
    /// <c>Uri.EscapeDataString</c> encoding that link's own token value went through - hand-rolled
    /// rather than pulling in <c>Microsoft.AspNetCore.WebUtilities</c> for one small parse, since
    /// this test project doesn't otherwise reference the ASP.NET Core shared framework.
    /// </summary>
    public static Dictionary<string, string> ParseLinkQuery(string link)
    {
        var query = new Uri(link).Query.TrimStart('?');
        return query
            .Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(pair => pair.Split('=', 2))
            .ToDictionary(parts => parts[0], parts => Uri.UnescapeDataString(parts[1]));
    }
}
