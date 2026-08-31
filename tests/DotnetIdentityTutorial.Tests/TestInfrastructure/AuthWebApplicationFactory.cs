using DotnetIdentityTutorial.Data;
using DotnetIdentityTutorial.Services.Interfaces;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Time.Testing;
using Testcontainers.PostgreSql;

namespace DotnetIdentityTutorial.Tests.TestInfrastructure;

/// <summary>
/// Boots the real <c>DotnetIdentityTutorial</c> <c>Program</c> pipeline (JWT Bearer auth, rate
/// limiting, ProblemDetails, the whole <c>AuthController</c>) through
/// <see cref="Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory{TEntryPoint}"/>'s
/// <c>TestServer</c>, the first branch where doing so is actually meaningful - JWT Bearer
/// authentication and permission claims genuinely resolve now. <c>Program</c> is already a
/// public, global-namespace type (top-level statements compiled with an explicit public
/// accessibility in this SDK), so no change to the production <c>Program.cs</c> was needed to
/// make it referenceable from this test project.
///
/// Three things are swapped in <see cref="ConfigureWebHost"/>, following the same
/// remove-then-re-add pattern as every "override a service for testing" example in the ASP.NET
/// Core docs, applied to the exact <see cref="IServiceCollection"/> <c>Program.cs</c> itself
/// populated (this callback runs after that code, before <c>Build()</c>):
/// <list type="bullet">
/// <item><description><c>AppDbContext</c> is repointed at a dedicated Testcontainers-provisioned
/// <c>postgres:16</c> instance instead of the connection string in <c>appsettings.json</c> - real
/// EF Core mapping, real migrations, real database-enforced constraints.</description></item>
/// <item><description><see cref="IEmailService"/> is replaced by <see cref="FakeEmailService"/>
/// so a test can read the real confirmation/reset link.</description></item>
/// <item><description><see cref="TimeProvider"/> is replaced by a shared
/// <see cref="Microsoft.Extensions.Time.Testing.FakeTimeProvider"/> so a lockout test can attempt
/// to advance time without a real wait - see the account-lockout test's own remarks for why this
/// alone does not reach ASP.NET Core Identity's own lockout clock.</description></item>
/// </list>
///
/// <c>Program.cs</c>'s own migration/seeding block (<c>dbContext.Database.MigrateAsync()</c> then
/// <c>DbInitializer.SeedAsync</c>) runs unconditionally on every startup, including under this
/// test host - nothing here skips or disables it, so every test that uses this factory starts
/// from a freshly migrated and seeded (but otherwise empty of application data) database.
///
/// One dedicated container per factory instance, and every test class below gets its own
/// <c>IClassFixture&lt;AuthWebApplicationFactory&gt;</c> rather than sharing one across multiple
/// test classes - the "auth" rate limiter's fixed window is in-memory, keyed by client IP, and
/// shared by every request the app instance handles regardless of which endpoint it hit; without
/// per-scenario isolation, the rate-limiter test's and the lockout test's own Login/ForgotPassword
/// calls would silently count against each other's window.
/// </summary>
public sealed class AuthWebApplicationFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    private readonly PostgreSqlContainer _postgresContainer = new PostgreSqlBuilder("postgres:16")
        .WithDatabase("dotnet_identity_tutorial_auth_e2e_test")
        .WithUsername("test")
        .WithPassword("test")
        .Build();

    private readonly Action<IServiceCollection>? _configureAdditionalServices;

    /// <summary>
    /// Shared with the app's own DI container via <see cref="ConfigureWebHost"/> below, so
    /// application code that resolves <c>TimeProvider</c> from DI (e.g. <c>TokenService</c>'s
    /// expiry computations) sees the same clock a test can advance. Seeded from the real current
    /// time rather than an arbitrary fixed date: the JWT Bearer middleware's own lifetime
    /// validation (<c>TokenValidationParameters.ValidateLifetime</c>, framework code in
    /// <c>Microsoft.IdentityModel.Tokens</c>) is not wired to this <see cref="TimeProvider"/> at
    /// all in <c>Program.cs</c> - it checks a token's <c>exp</c> claim against the real system
    /// clock regardless. Seeding this fake clock far from the real one (an earlier attempt used a
    /// fixed 2026-01-01 baseline, matching <c>TokenServiceFixture</c>'s pattern, which never
    /// exercises real JWT Bearer validation) made every access token this factory issues look
    /// already-expired the moment a protected endpoint validated it. None of this branch's tests
    /// need the access-token clock itself to diverge from real time, only Identity's own lockout
    /// window would benefit from that - and that window turned out not to be reachable through
    /// this seam at all, see <c>AuthAccountLockoutE2ETests</c>' own remarks.
    /// </summary>
    public FakeTimeProvider TimeProvider { get; } = new(DateTimeOffset.UtcNow);

    public FakeEmailService EmailService { get; } = new();

    /// <summary>
    /// The only public constructor, deliberately parameterless: xUnit's
    /// <c>IClassFixture&lt;T&gt;</c> requires exactly one public constructor to reflect over, and
    /// every test class here except <c>AuthAccountLockoutE2ETests</c> goes through that path.
    /// </summary>
    public AuthWebApplicationFactory()
    {
    }

    private AuthWebApplicationFactory(Action<IServiceCollection> configureAdditionalServices)
    {
        _configureAdditionalServices = configureAdditionalServices;
    }

    /// <summary>
    /// For a scenario that needs to relax an orthogonal cross-cutting concern to isolate the one
    /// it's actually testing, applied after this factory's own database/email/time overrides -
    /// see <c>AuthAccountLockoutE2ETests</c>, the one test that uses this, to disable the "auth"
    /// rate limiter for its own app instance without touching the production
    /// <c>RateLimiterPolicies</c> class (that policy's own correctness is
    /// <c>AuthRateLimiterE2ETests</c>' job, not this one's). Not reachable through
    /// <c>IClassFixture&lt;T&gt;</c> - that test class constructs its factory directly instead,
    /// see the private constructor above for why the public one has to stay parameterless.
    /// </summary>
    public static AuthWebApplicationFactory WithAdditionalServices(Action<IServiceCollection> configureAdditionalServices)
        => new(configureAdditionalServices);

    public Task InitializeAsync() => _postgresContainer.StartAsync();

    Task IAsyncLifetime.DisposeAsync() => DisposeAsync().AsTask();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");

        builder.ConfigureServices(services =>
        {
            services.RemoveAll<DbContextOptions<AppDbContext>>();
            services.RemoveAll<AppDbContext>();
            services.AddDbContext<AppDbContext>(options => options.UseNpgsql(_postgresContainer.GetConnectionString()));

            services.RemoveAll<IEmailService>();
            services.AddSingleton<IEmailService>(EmailService);

            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider>(TimeProvider);

            _configureAdditionalServices?.Invoke(services);
        });
    }

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        await _postgresContainer.DisposeAsync();
    }
}
