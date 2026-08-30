using DotnetIdentityTutorial.Data;
using DotnetIdentityTutorial.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Testcontainers.PostgreSql;

namespace DotnetIdentityTutorial.Tests.Data;

/// <summary>
/// The one feature/identity-setup checklist item not already covered elsewhere: that the
/// initial migration applies cleanly against a real PostgreSQL instance, and that
/// <see cref="DbInitializer.SeedAsync"/> is idempotent - running it twice against the same
/// database must not duplicate roles or permissions, and must not throw on an already-existing
/// <c>RolePermission</c> row. This is deliberately an integration test against a real
/// Testcontainers-provisioned Postgres rather than an in-memory provider or a mock: the
/// migration itself, and Postgres's own unique constraints, are exactly what's being verified.
/// </summary>
public class DbInitializerTests : IAsyncLifetime
{
    private static readonly (string Resource, string Action)[] ExpectedBaselinePermissions =
    [
        ("USER", "READ"),
        ("USER", "WRITE"),
        ("ROLE", "READ"),
        ("ROLE", "WRITE"),
        ("PERMISSION", "READ"),
        ("PERMISSION", "WRITE"),
        ("AUDIT", "READ"),
    ];

    private readonly PostgreSqlContainer _postgresContainer = new PostgreSqlBuilder("postgres:16")
        .WithDatabase("dotnet_identity_tutorial_test")
        .WithUsername("test")
        .WithPassword("test")
        .Build();

    public Task InitializeAsync() => _postgresContainer.StartAsync();

    public Task DisposeAsync() => _postgresContainer.DisposeAsync().AsTask();

    /// <summary>
    /// Mirrors the DI shape Program.cs builds: AppDbContext against the real connection
    /// string, plus the minimal Identity registration DbInitializer.SeedAsync needs
    /// (RoleManager&lt;ApplicationRole&gt;, backed by the same AppDbContext).
    /// </summary>
    private ServiceProvider BuildServiceProvider()
    {
        var services = new ServiceCollection();

        services.AddLogging();

        services.AddDbContext<AppDbContext>(options =>
            options.UseNpgsql(_postgresContainer.GetConnectionString()));

        services.AddIdentityCore<ApplicationUser>()
            .AddRoles<ApplicationRole>()
            .AddEntityFrameworkStores<AppDbContext>();

        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task MigrateThenSeedTwice_MigrationAppliesCleanlyAndSeedingIsIdempotent()
    {
        await using var serviceProvider = BuildServiceProvider();
        using var scope = serviceProvider.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        // "Migration applies cleanly" half of the checklist item: this is the assertion,
        // since MigrateAsync throwing is exactly what "does not apply cleanly" would look
        // like, and an uncaught exception here fails the test on its own.
        await dbContext.Database.MigrateAsync();

        // First seeding pass, against a freshly migrated, empty database.
        await DbInitializer.SeedAsync(scope.ServiceProvider);

        var roleNamesAfterFirst = await dbContext.Roles
            .Select(r => r.NormalizedName)
            .ToListAsync();
        var permissionsAfterFirst = await dbContext.Permissions
            .Select(p => new { p.Resource, p.Action })
            .ToListAsync();
        var adminRole = await dbContext.Roles.SingleAsync(r => r.NormalizedName == "ADMIN");
        var adminRolePermissionCountAfterFirst = await dbContext.RolePermissions
            .CountAsync(rp => rp.RoleId == adminRole.Id);

        Assert.Equal(2, roleNamesAfterFirst.Count);
        Assert.Contains("ADMIN", roleNamesAfterFirst);
        Assert.Contains("USER", roleNamesAfterFirst);

        Assert.Equal(ExpectedBaselinePermissions.Length, permissionsAfterFirst.Count);
        foreach (var (resource, action) in ExpectedBaselinePermissions)
        {
            Assert.Contains(permissionsAfterFirst, p => p.Resource == resource && p.Action == action);
        }

        Assert.Equal(ExpectedBaselinePermissions.Length, adminRolePermissionCountAfterFirst);

        // Second seeding pass against the same, now-populated database. A naive
        // implementation relying on try/catch around a unique-constraint violation could
        // still make this not throw while masking a real bug; DbInitializer is
        // check-then-insert, so the correct behavior is that nothing here changes at all.
        await DbInitializer.SeedAsync(scope.ServiceProvider);

        var roleCountAfterSecond = await dbContext.Roles.CountAsync();
        var permissionCountAfterSecond = await dbContext.Permissions.CountAsync();
        var adminRolePermissionCountAfterSecond = await dbContext.RolePermissions
            .CountAsync(rp => rp.RoleId == adminRole.Id);

        Assert.Equal(roleNamesAfterFirst.Count, roleCountAfterSecond);
        Assert.Equal(permissionsAfterFirst.Count, permissionCountAfterSecond);
        Assert.Equal(adminRolePermissionCountAfterFirst, adminRolePermissionCountAfterSecond);
    }
}
