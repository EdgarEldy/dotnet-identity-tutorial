using System.Net;
using System.Net.Http.Json;
using DotnetIdentityTutorial.Tests.TestInfrastructure;

namespace DotnetIdentityTutorial.Tests.Controllers;

/// <summary>
/// Proves the named "auth" fixed-window rate limiter (<see cref="RateLimiting.RateLimiterPolicies"/>
/// - 5 requests/minute per client IP) is actually wired into the real HTTP pipeline, not just
/// declared. Uses its own <see cref="AuthWebApplicationFactory"/> instance (see the factory's own
/// remarks) so this class's calls can't be pushed over the threshold by, or push over the
/// threshold, any other test class's calls against the same in-memory limiter.
/// </summary>
public sealed class AuthRateLimiterE2ETests : IClassFixture<AuthWebApplicationFactory>
{
    private readonly AuthWebApplicationFactory _factory;

    public AuthRateLimiterE2ETests(AuthWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task ForgotPassword_SixthRequestWithinTheWindow_Returns429WithProblemDetails()
    {
        var client = _factory.CreateClient();
        var email = $"{Guid.NewGuid():N}@example.com";

        // ForgotPasswordAsync always responds 204 No Content regardless of whether the email
        // matches an account (see its own anti-enumeration remarks), so a made-up email is fine
        // here and creates no state that could leak into another test.
        for (var i = 0; i < 5; i++)
        {
            var response = await client.PostAsJsonAsync(
                "/api/v1/Auth/ForgotPassword", new { Email = email }, AuthTestHelpers.JsonOptions);
            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        }

        // The 6th request in the same one-minute window, same client IP, crosses the
        // PermitLimit = 5 configured in RateLimiterPolicies.AddAuthPolicy.
        var sixthResponse = await client.PostAsJsonAsync(
            "/api/v1/Auth/ForgotPassword", new { Email = email }, AuthTestHelpers.JsonOptions);

        Assert.Equal(HttpStatusCode.TooManyRequests, sixthResponse.StatusCode);
        Assert.Equal("application/problem+json", sixthResponse.Content.Headers.ContentType?.MediaType);
    }
}
