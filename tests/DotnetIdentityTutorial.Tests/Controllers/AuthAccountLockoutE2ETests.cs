using System.Net;
using System.Net.Http.Json;
using DotnetIdentityTutorial.Identity;
using DotnetIdentityTutorial.RateLimiting;
using DotnetIdentityTutorial.Tests.TestInfrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System.Threading.RateLimiting;

namespace DotnetIdentityTutorial.Tests.Controllers;

/// <summary>
/// Proves Identity's own account lockout (<c>Lockout.MaxFailedAccessAttempts = 5</c>,
/// <c>Lockout.DefaultLockoutTimeSpan = 15 minutes</c>, configured on <c>AddIdentity&lt;...&gt;()</c>
/// in <c>Program.cs</c>) is actually enforced through <c>AuthController.Login</c>, and that it
/// lifts once enough time has passed - without a real 15-minute wait.
///
/// <b>Why the "auth" rate limiter is disabled for this one test's app instance:</b> proving
/// lockout genuinely needs more than five <c>Login</c> calls in a row (five wrong-password
/// attempts, one more with the correct password while still locked, one more after unlocking =
/// seven), but the same "auth" named policy (<see cref="RateLimiterPolicies"/>) that protects
/// <c>Register</c>/<c>ForgotPassword</c> also covers <c>Login</c>, at 5 requests/minute per
/// client IP - fewer than this scenario needs from a single account within one window. Rather
/// than let an orthogonal cross-cutting concern (already covered exhaustively by
/// <see cref="AuthRateLimiterE2ETests"/>) fail this test with an unrelated 429, this factory
/// instance replaces the "auth" policy with an always-permit limiter, through the same
/// remove-then-re-add <see cref="IServiceCollection"/> pattern <c>AuthWebApplicationFactory</c>
/// itself uses, not by touching the production <c>RateLimiterPolicies</c> class.
///
/// <b>A documented deviation from the literal "use FakeTimeProvider" instruction:</b> ASP.NET
/// Core Identity's own <c>UserManager&lt;TUser&gt;.AccessFailedAsync</c>/<c>IsLockedOutAsync</c>
/// (in <c>Microsoft.Extensions.Identity.Core</c> 10.0.11, confirmed by decompiling the installed
/// package) call <c>DateTimeOffset.UtcNow</c> directly - Identity has no injectable
/// <c>TimeProvider</c> seam for lockout timing in this SDK version, so advancing
/// <see cref="AuthWebApplicationFactory.TimeProvider"/> has no effect on when a lockout actually
/// lifts; that substitution only reaches code this project itself authored (e.g.
/// <c>TokenService</c>'s expiry math), not Identity's own internals. To still avoid a real wait,
/// this test moves the persisted <c>LockoutEnd</c> into the past directly through the same
/// <c>UserManager&lt;ApplicationUser&gt;</c> the production code uses
/// (<c>SetLockoutEndDateAsync</c>) - deterministic, no <c>Task.Delay</c>/<c>Thread.Sleep</c>, and
/// it exercises exactly the "<c>LockoutEnd</c> has passed" condition <c>IsLockedOutAsync</c>
/// checks, the same effect fifteen real minutes elapsing would have had.
/// </summary>
public sealed class AuthAccountLockoutE2ETests : IAsyncLifetime
{
    private readonly AuthWebApplicationFactory _factory = AuthWebApplicationFactory.WithAdditionalServices(services =>
    {
        services.RemoveAll<IConfigureOptions<RateLimiterOptions>>();
        services.Configure<RateLimiterOptions>(options =>
        {
            options.ConfigureRejectionResponse();
            options.AddPolicy(RateLimiterPolicies.Auth, httpContext => RateLimitPartition.GetNoLimiter(
                httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown"));
        });
    });

    public Task InitializeAsync() => _factory.InitializeAsync();

    public Task DisposeAsync() => ((IAsyncLifetime)_factory).DisposeAsync();

    [Fact]
    public async Task Login_AfterExceedingMaxFailedAttempts_LocksOutThenAllowsLoginAgainOnceLockoutEndHasPassed()
    {
        var client = _factory.CreateClient();
        var email = $"{Guid.NewGuid():N}@example.com";
        const string correctPassword = "Passw0rd1";
        const string wrongPassword = "WrongPass1";

        await AuthTestHelpers.RegisterAndConfirmAsync(client, _factory.EmailService, email, correctPassword);

        // Lockout.MaxFailedAccessAttempts = 5 (Program.cs). SignInManager.CheckPasswordSignInAsync
        // already returns SignInResult.LockedOut on the attempt that crosses the threshold (it
        // re-checks IsLockedOutAsync immediately after incrementing AccessFailedCount), so every
        // one of these five wrong-password attempts surfaces the same 422 BusinessRuleException
        // either way ("invalid credentials" vs "locked out") - the real proof of lockout is the
        // correct-password attempt right after.
        for (var i = 0; i < 5; i++)
        {
            var response = await client.PostAsJsonAsync(
                "/api/v1/Auth/Login", new { Email = email, Password = wrongPassword }, AuthTestHelpers.JsonOptions);
            Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        }

        // The account is now locked: even the CORRECT password is rejected while LockoutEnd is
        // in the future.
        var stillLockedResponse = await client.PostAsJsonAsync(
            "/api/v1/Auth/Login", new { Email = email, Password = correctPassword }, AuthTestHelpers.JsonOptions);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, stillLockedResponse.StatusCode);

        // Simulate "past the lockout window" deterministically - see this class's own remarks
        // for why advancing _factory.TimeProvider cannot reach Identity's own lockout clock.
        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userManager.FindByEmailAsync(email)
                ?? throw new InvalidOperationException("Test setup failed: registered user was not found.");
            await userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddMinutes(-1));
        }

        var unlockedResponse = await client.PostAsJsonAsync(
            "/api/v1/Auth/Login", new { Email = email, Password = correctPassword }, AuthTestHelpers.JsonOptions);
        Assert.Equal(HttpStatusCode.OK, unlockedResponse.StatusCode);
    }
}
