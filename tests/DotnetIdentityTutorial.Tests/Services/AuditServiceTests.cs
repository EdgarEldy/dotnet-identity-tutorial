using DotnetIdentityTutorial.Data;
using DotnetIdentityTutorial.Exceptions;
using DotnetIdentityTutorial.Identity;
using DotnetIdentityTutorial.Models;
using DotnetIdentityTutorial.Services.Implementations;
using DotnetIdentityTutorial.Services.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Testcontainers.PostgreSql;

namespace DotnetIdentityTutorial.Tests.Services;

/// <summary>
/// Exercises <see cref="IAuditService.GetAuditLogsAsync"/> directly against a real
/// Testcontainers-provisioned PostgreSQL instance, the same pattern as
/// <see cref="RbacServiceTests"/>/<see cref="UserAdminServiceTests"/>. <see cref="IAuditService.LogAsync"/>'s
/// own write path (actor resolution, action/entity-type/entity-id shape per call site) is already
/// covered by the audit-trail assertions added to those two classes; this class is about the read
/// side's own query logic: bounds-checked pagination (mirroring
/// <c>UserAdminServiceTests.GetUsersAsync_InvalidPageOrPageSize_ThrowsBusinessRuleException</c>),
/// the actor/entity-type filters, and newest-first ordering.
///
/// Most fixture rows here are inserted directly against <see cref="AppDbContext.AuditLogs"/>
/// rather than through <see cref="IAuditService.LogAsync"/>, deliberately: <c>LogAsync</c>
/// resolves the acting user from an ambient <c>HttpContext</c> via <c>IHttpContextAccessor</c>,
/// and there is no real HTTP request in a service-layer test to supply one, so every row it wrote
/// here would carry a null actor - useless for proving the actor filter narrows results. A direct
/// insert lets each fixture row carry an explicit, real <see cref="AuditLog.ActorUserId"/>
/// (a real, persisted <see cref="ApplicationUser"/> id - <see cref="AuditLog"/>'s foreign key is
/// enforced, not just a bare column) and an explicit <see cref="AuditLog.CreatedAt"/> for ordering,
/// exactly as this branch's own task description sanctions for setting up filtering/ordering
/// fixtures specifically.
/// </summary>
public class AuditServiceTests : IClassFixture<AuditServiceFixture>
{
    private readonly AuditServiceFixture _fixture;

    public AuditServiceTests(AuditServiceFixture fixture)
    {
        _fixture = fixture;
    }

    [Theory]
    [InlineData(0, 20)]
    [InlineData(-1, 20)]
    [InlineData(1, 0)]
    [InlineData(1, -5)]
    [InlineData(1, 101)]
    public async Task GetAuditLogsAsync_InvalidPageOrPageSize_ThrowsBusinessRuleException(int page, int pageSize)
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var auditService = scope.ServiceProvider.GetRequiredService<IAuditService>();

        await Assert.ThrowsAsync<BusinessRuleException>(
            () => auditService.GetAuditLogsAsync(page, pageSize, actorUserId: null, entityType: null));
    }

    [Fact]
    public async Task GetAuditLogsAsync_RowsInsertedOutOfOrder_ReturnsThemNewestFirst()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var auditService = scope.ServiceProvider.GetRequiredService<IAuditService>();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var entityType = Unique("ENTITY");
        var baseline = _fixture.TimeProvider.GetUtcNow();

        // Three rows, deliberately inserted out of chronological order, each carrying an explicit
        // CreatedAt far enough apart that ordering can't come out right by coincidence. Filtered
        // by a unique entityType (rather than asserting on the unfiltered result set) so this
        // test's own rows can be isolated from whatever other tests in this IClassFixture-shared
        // container have already inserted.
        AddAuditLog(dbContext, entityType, "Second", baseline.AddMinutes(1));
        AddAuditLog(dbContext, entityType, "Third", baseline.AddMinutes(2));
        AddAuditLog(dbContext, entityType, "First", baseline);
        await dbContext.SaveChangesAsync();

        var (logs, totalCount) = await auditService.GetAuditLogsAsync(page: 1, pageSize: 20, actorUserId: null, entityType: entityType);

        Assert.Equal(3, totalCount);
        Assert.Equal(["Third", "Second", "First"], logs.Select(l => l.EntityId));
    }

    [Fact]
    public async Task GetAuditLogsAsync_EntityTypeFilter_NarrowsResultsToThatEntityTypeOnly()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var auditService = scope.ServiceProvider.GetRequiredService<IAuditService>();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var matchingEntityType = Unique("MATCH");
        var otherEntityType = Unique("OTHER");
        var now = _fixture.TimeProvider.GetUtcNow();

        AddAuditLog(dbContext, matchingEntityType, "1", now);
        AddAuditLog(dbContext, matchingEntityType, "2", now);
        AddAuditLog(dbContext, otherEntityType, "3", now);
        await dbContext.SaveChangesAsync();

        var (logs, totalCount) = await auditService.GetAuditLogsAsync(page: 1, pageSize: 20, actorUserId: null, entityType: matchingEntityType);

        Assert.Equal(2, totalCount);
        Assert.Equal(2, logs.Count);
        Assert.All(logs, l => Assert.Equal(matchingEntityType, l.EntityType));
    }

    [Fact]
    public async Task GetAuditLogsAsync_ActorUserIdFilter_NarrowsResultsToThatActorOnly()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var auditService = scope.ServiceProvider.GetRequiredService<IAuditService>();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var actorOne = await CreateUserAsync(userManager);
        var actorTwo = await CreateUserAsync(userManager);
        var entityType = Unique("ENTITY");
        var now = _fixture.TimeProvider.GetUtcNow();

        AddAuditLog(dbContext, entityType, "1", now, actorOne.Id);
        AddAuditLog(dbContext, entityType, "2", now, actorOne.Id);
        AddAuditLog(dbContext, entityType, "3", now, actorTwo.Id);
        await dbContext.SaveChangesAsync();

        var (logs, totalCount) = await auditService.GetAuditLogsAsync(page: 1, pageSize: 20, actorUserId: actorOne.Id, entityType: entityType);

        Assert.Equal(2, totalCount);
        Assert.All(logs, l => Assert.Equal(actorOne.Id, l.ActorUserId));
    }

    [Fact]
    public async Task GetAuditLogsAsync_PageSizeSmallerThanTotal_ReturnsOnlyThatManyItemsWithAccurateTotalCount()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var auditService = scope.ServiceProvider.GetRequiredService<IAuditService>();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var entityType = Unique("ENTITY");
        var now = _fixture.TimeProvider.GetUtcNow();

        AddAuditLog(dbContext, entityType, "1", now);
        AddAuditLog(dbContext, entityType, "2", now.AddMinutes(1));
        AddAuditLog(dbContext, entityType, "3", now.AddMinutes(2));
        await dbContext.SaveChangesAsync();

        var (logs, totalCount) = await auditService.GetAuditLogsAsync(page: 1, pageSize: 2, actorUserId: null, entityType: entityType);

        Assert.Equal(3, totalCount);
        Assert.Equal(2, logs.Count);
        // Newest-first: page 1 of size 2 should be entries "3" then "2", not "1".
        Assert.Equal(["3", "2"], logs.Select(l => l.EntityId));
    }

    /// <summary>
    /// <c>LogAsync</c>'s own actor-resolution/serialization behavior is exercised here through the
    /// real write path (unlike every other test in this class), confirming <c>GetAuditLogsAsync</c>
    /// can read back exactly what <c>LogAsync</c> wrote, details included - the two are covered
    /// together once, rather than asserting the same round-trip redundantly in every test above.
    /// </summary>
    [Fact]
    public async Task GetAuditLogsAsync_AfterLogAsync_ReturnsTheLoggedRowWithNullActorAndSerializedDetails()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var auditService = scope.ServiceProvider.GetRequiredService<IAuditService>();
        var entityType = Unique("ENTITY");
        var entityId = Guid.NewGuid().ToString();

        // No ambient HttpContext in this service-layer test, so the actor resolves to null - the
        // same documented, non-throwing behavior RbacServiceTests/UserAdminServiceTests rely on.
        await auditService.LogAsync("Create", entityType, entityId, new { Reason = "test" });

        var (logs, totalCount) = await auditService.GetAuditLogsAsync(page: 1, pageSize: 20, actorUserId: null, entityType: entityType);

        Assert.Equal(1, totalCount);
        var log = Assert.Single(logs);
        Assert.Equal("Create", log.Action);
        Assert.Equal(entityId, log.EntityId);
        Assert.Null(log.ActorUserId);
        Assert.NotNull(log.Details);
        // AuditService.LogAsync serializes with plain System.Text.Json defaults (no camelCase
        // naming policy applied), so the C# property's own casing is preserved verbatim. Parsed
        // rather than compared as a raw substring: Postgres' own jsonb column normalizes the
        // stored text (e.g. inserting a space after ":"), so the exact byte-for-byte JSON
        // System.Text.Json produced is not what comes back out.
        using var details = System.Text.Json.JsonDocument.Parse(log.Details!);
        Assert.Equal("test", details.RootElement.GetProperty("Reason").GetString());
    }

    private static string Unique(string prefix) => $"{prefix}_{Guid.NewGuid():N}".ToUpperInvariant();

    private static void AddAuditLog(AppDbContext dbContext, string entityType, string entityId, DateTimeOffset createdAt, int? actorUserId = null)
    {
        dbContext.AuditLogs.Add(new AuditLog
        {
            ActorUserId = actorUserId,
            Action = "Create",
            EntityType = entityType,
            EntityId = entityId,
            Details = null,
            CreatedAt = createdAt,
        });
    }

    private static async Task<ApplicationUser> CreateUserAsync(UserManager<ApplicationUser> userManager)
    {
        var email = $"{Guid.NewGuid():N}@example.com";
        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            FirstName = "Test",
            LastName = "User",
            EmailConfirmed = true,
        };

        var result = await userManager.CreateAsync(user, "Passw0rd1");
        if (!result.Succeeded)
        {
            throw new InvalidOperationException(
                $"Failed to create test user: {string.Join(", ", result.Errors.Select(e => e.Description))}");
        }

        return user;
    }
}

/// <summary>
/// Shared Testcontainers PostgreSQL instance, DI container, and <see cref="FakeTimeProvider"/> for
/// <see cref="AuditServiceTests"/>. Registers Identity (not just <see cref="AppDbContext"/>) so
/// <see cref="AuditServiceTests.GetAuditLogsAsync_ActorUserIdFilter_NarrowsResultsToThatActorOnly"/>
/// can create real <see cref="ApplicationUser"/> rows for <see cref="AuditLog.ActorUserId"/>'s
/// enforced foreign key to reference - the same reasoning
/// <see cref="RbacServiceFixture"/>/<see cref="UserAdminServiceFixture"/> already establish.
/// </summary>
public sealed class AuditServiceFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer _postgresContainer = new PostgreSqlBuilder("postgres:16")
        .WithDatabase("dotnet_identity_tutorial_audit_test")
        .WithUsername("test")
        .WithPassword("test")
        .Build();

    public FakeTimeProvider TimeProvider { get; } = new(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));

    public ServiceProvider ServiceProvider { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        await _postgresContainer.StartAsync();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<TimeProvider>(TimeProvider);
        services.AddHttpContextAccessor();

        services.AddDbContext<AppDbContext>(options =>
            options.UseNpgsql(_postgresContainer.GetConnectionString()));

        services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
            {
                options.Password.RequireDigit = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequiredLength = 8;
            })
            .AddEntityFrameworkStores<AppDbContext>()
            .AddDefaultTokenProviders();

        services.AddScoped<IAuditService, AuditService>();

        ServiceProvider = services.BuildServiceProvider();

        using var scope = ServiceProvider.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await dbContext.Database.MigrateAsync();
    }

    public async Task DisposeAsync()
    {
        await ServiceProvider.DisposeAsync();
        await _postgresContainer.DisposeAsync();
    }
}
