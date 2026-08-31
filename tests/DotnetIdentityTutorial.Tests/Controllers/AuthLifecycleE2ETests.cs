using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using DotnetIdentityTutorial.Dtos.Auth;
using DotnetIdentityTutorial.Tests.TestInfrastructure;

namespace DotnetIdentityTutorial.Tests.Controllers;

/// <summary>
/// The one true end-to-end test this branch's checklist asks for: register -&gt; confirm ->
/// login -&gt; call a protected endpoint -&gt; refresh -&gt; logout -&gt; confirm rejection
/// afterward, entirely through <see cref="AuthWebApplicationFactory"/>'s real HTTP pipeline (JWT
/// Bearer auth, the blacklist check in <c>Program.cs</c>'s <c>OnTokenValidated</c>, everything).
/// No step here calls a service directly - every assertion is against the actual HTTP
/// status code and body a real client would see.
/// </summary>
public sealed class AuthLifecycleE2ETests : IClassFixture<AuthWebApplicationFactory>
{
    private readonly AuthWebApplicationFactory _factory;

    public AuthLifecycleE2ETests(AuthWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task FullLifecycle_RegisterConfirmLoginProtectedEndpointRefreshLogout_WorksEndToEnd()
    {
        var client = _factory.CreateClient();
        var email = $"{Guid.NewGuid():N}@example.com";
        const string password = "Passw0rd1";

        // Register: 202 Accepted, no usable resource yet - see AuthController.Register's own
        // remarks. The confirmation link is captured by FakeEmailService instead of only being
        // logged, so the real userId/token pair can be extracted below.
        var (userId, confirmationToken) = await AuthTestHelpers.RegisterAsync(client, _factory.EmailService, email, password);

        // Confirm: consumes the real, stateless UserManager-generated token.
        await AuthTestHelpers.ConfirmEmailAsync(client, userId, confirmationToken);

        // Login: RequireConfirmedAccount = true means this would have failed with 422 before the
        // confirmation step above - a real proof the confirmation gate is not cosmetic.
        var loginResponse = await client.PostAsJsonAsync(
            "/api/v1/Auth/Login", new { Email = email, Password = password }, AuthTestHelpers.JsonOptions);
        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);

        var tokens = await loginResponse.Content.ReadFromJsonAsync<TokenResponse>(AuthTestHelpers.JsonOptions);
        Assert.NotNull(tokens);
        Assert.False(string.IsNullOrWhiteSpace(tokens!.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(tokens.RefreshToken));

        // Call a protected endpoint with the freshly issued access token - Me needs nothing
        // beyond being authenticated, no RBAC permission required.
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        var meResponse = await client.GetAsync("/api/v1/Auth/Me");
        Assert.Equal(HttpStatusCode.OK, meResponse.StatusCode);

        // Refresh: exchanges the refresh token for a brand-new pair in the same family. Refresh
        // itself is public (no bearer header required), but leaving the header attached is
        // harmless - the endpoint doesn't require it.
        var refreshResponse = await client.PostAsJsonAsync(
            "/api/v1/Auth/Refresh", new { RefreshToken = tokens.RefreshToken }, AuthTestHelpers.JsonOptions);
        Assert.Equal(HttpStatusCode.OK, refreshResponse.StatusCode);

        var refreshedTokens = await refreshResponse.Content.ReadFromJsonAsync<TokenResponse>(AuthTestHelpers.JsonOptions);
        Assert.NotNull(refreshedTokens);
        Assert.NotEqual(tokens.AccessToken, refreshedTokens!.AccessToken);
        Assert.NotEqual(tokens.RefreshToken, refreshedTokens.RefreshToken);

        // Logout with the ORIGINAL (pre-refresh) access token, not the rotated one:
        // TokenService.RevokeAsync blacklists only the specific jti presented at logout, so this
        // proves that access token specifically stops working immediately afterward, per
        // AuthController.Logout reading its own jti/exp claims off the caller's current bearer
        // token.
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        var logoutResponse = await client.PostAsync("/api/v1/Auth/Logout", content: null);
        Assert.Equal(HttpStatusCode.NoContent, logoutResponse.StatusCode);

        // Immediately retry the same protected endpoint with that now-blacklisted access token -
        // rejected right away by the OnTokenValidated jti check, not just eventually once the
        // token's own exp claim passes.
        var meAfterLogoutResponse = await client.GetAsync("/api/v1/Auth/Me");
        Assert.Equal(HttpStatusCode.Unauthorized, meAfterLogoutResponse.StatusCode);
    }

    /// <summary>
    /// Registering an email that already has an account must return the exact same 202 Accepted
    /// a fresh registration gets, never a distinguishable error - otherwise Register becomes a
    /// user-enumeration oracle, the same class of leak <c>ForgotPasswordAsync</c> is designed to
    /// prevent. Uses its own factory instance (not the shared one the lifecycle test above uses)
    /// so this test's two Register calls don't count against that test's rate-limit budget.
    /// </summary>
    [Fact]
    public async Task Register_WithAnAlreadyRegisteredEmail_StillReturnsAccepted()
    {
        await using var factory = new AuthWebApplicationFactory();
        await factory.InitializeAsync();
        var client = factory.CreateClient();
        var email = $"{Guid.NewGuid():N}@example.com";
        const string password = "Passw0rd1";

        await AuthTestHelpers.RegisterAsync(client, factory.EmailService, email, password);

        var duplicateResponse = await client.PostAsJsonAsync(
            "/api/v1/Auth/Register",
            new { Email = email, Password = password, FirstName = "Ada", LastName = "Lovelace" },
            AuthTestHelpers.JsonOptions);

        Assert.Equal(HttpStatusCode.Accepted, duplicateResponse.StatusCode);
    }
}
