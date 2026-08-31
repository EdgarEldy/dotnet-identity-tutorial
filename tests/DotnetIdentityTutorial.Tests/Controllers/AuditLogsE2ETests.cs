using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using DotnetIdentityTutorial.Dtos.AuditLog;
using DotnetIdentityTutorial.Dtos.Auth;
using DotnetIdentityTutorial.Dtos.Rbac;
using DotnetIdentityTutorial.Identity;
using DotnetIdentityTutorial.Services.Interfaces;
using DotnetIdentityTutorial.Tests.TestInfrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace DotnetIdentityTutorial.Tests.Controllers;

/// <summary>
/// Proves <c>GET /api/v1/AuditLogs</c> is genuinely gated by the <c>"AUDIT:READ"</c> permission
/// policy through the real HTTP pipeline (JWT Bearer authentication + <c>PermissionAuthorizationHandler</c>),
/// not merely by the presence of the <c>[Authorize(Policy = "AUDIT:READ")]</c> attribute at the
/// source level, and that the <c>X-Total-Count</c> pagination header this project uses instead of
/// a response envelope is actually set on the wire.
///
/// Unlike <c>RbacServiceTests</c>/<c>UserAdminServiceTests</c> (written on feature/rbac, before
/// JWT Bearer authentication or the claims/policy pipeline existed - see their own remarks),
/// feature/audit-logging is built after feature/token-lifecycle and feature/claims-and-
/// authorization have both already merged, so an end-to-end test through
/// <see cref="AuthWebApplicationFactory"/> is both possible and the established pattern this
/// project already uses for auth-adjacent endpoints (see <c>AuthLifecycleE2ETests</c>,
/// <c>MfaLifecycleE2ETests</c>) - there is no equivalent deviation to document here.
/// </summary>
public sealed class AuditLogsE2ETests : IClassFixture<AuthWebApplicationFactory>
{
    private readonly AuthWebApplicationFactory _factory;

    public AuditLogsE2ETests(AuthWebApplicationFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task GetAuditLogs_NoBearerToken_ReturnsUnauthorized()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/api/v1/AuditLogs");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task GetAuditLogs_AuthenticatedWithoutAuditReadPermission_ReturnsForbidden()
    {
        var client = _factory.CreateClient();
        var email = $"{Guid.NewGuid():N}@example.com";
        const string password = "Passw0rd1";
        var tokens = await AuthTestHelpers.RegisterConfirmAndLoginAsync(client, _factory.EmailService, email, password);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

        var response = await client.GetAsync("/api/v1/AuditLogs");

        // Self-registration only ever grants the seeded "USER" role, which carries no AUDIT:READ
        // permission - a plain authenticated user must not be able to read the audit trail.
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task GetAuditLogs_AuthenticatedAsAdmin_ReturnsOkWithPaginationHeaderAndRealData()
    {
        var client = _factory.CreateClient();
        var email = $"{Guid.NewGuid():N}@example.com";
        const string password = "Passw0rd1";
        await AuthTestHelpers.RegisterAndConfirmAsync(client, _factory.EmailService, email, password);

        // Promote the freshly registered account to ADMIN directly through UserManager, the same
        // sanctioned "test code may call a manager directly" pattern RbacServiceTests/
        // UserAdminServiceTests already establish, rather than standing up a second admin-
        // provisioning flow just for this test. DbInitializer seeds ADMIN with every baseline
        // permission at startup, including AUDIT:READ.
        string uniqueResource;
        using (var scope = _factory.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await userManager.FindByEmailAsync(email)
                ?? throw new InvalidOperationException("Test setup failed: registered user was not found.");
            var addToRoleResult = await userManager.AddToRoleAsync(user, "ADMIN");
            if (!addToRoleResult.Succeeded)
            {
                throw new InvalidOperationException(
                    $"Test setup failed: could not add ADMIN role: {string.Join(", ", addToRoleResult.Errors.Select(e => e.Description))}");
            }

            // Produce one real, findable audit row through the actual service layer (not a raw
            // AppDbContext insert) so the assertion below proves data genuinely flows end to end
            // through the real GET pipeline, not just that the endpoint returns 200 with an empty
            // list.
            uniqueResource = $"E2E_RES_{Guid.NewGuid():N}".ToUpperInvariant();
            var rbacService = scope.ServiceProvider.GetRequiredService<IRbacService>();
            await rbacService.CreatePermissionAsync(new PermissionRequest(uniqueResource, "READ"));
        }

        // Permission claims are baked into the JWT at sign-in time (README's own documented
        // staleness trade-off - see "Claims-based authorization"), so the role change above only
        // takes effect on a fresh login, not the token already issued during registration.
        var loginResponse = await client.PostAsJsonAsync(
            "/api/v1/Auth/Login", new { Email = email, Password = password }, AuthTestHelpers.JsonOptions);
        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);
        var tokens = await loginResponse.Content.ReadFromJsonAsync<TokenResponse>(AuthTestHelpers.JsonOptions);
        Assert.NotNull(tokens);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens!.AccessToken);

        var response = await client.GetAsync("/api/v1/AuditLogs?pageSize=100");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.TryGetValues("X-Total-Count", out var totalCountValues));
        var totalCount = int.Parse(totalCountValues!.Single());
        Assert.True(totalCount > 0);

        var logs = await response.Content.ReadFromJsonAsync<List<AuditLogResponse>>(AuthTestHelpers.JsonOptions);
        Assert.NotNull(logs);
        Assert.Contains(logs!, log => log.Action == "Create" && log.EntityType == "Permission" && log.Details != null && log.Details.Contains(uniqueResource));
    }
}
