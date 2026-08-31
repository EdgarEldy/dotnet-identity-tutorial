using DotnetIdentityTutorial.Data;
using DotnetIdentityTutorial.Dtos.Rbac;
using DotnetIdentityTutorial.Exceptions;
using DotnetIdentityTutorial.Identity;
using DotnetIdentityTutorial.Models;
using DotnetIdentityTutorial.Services.Implementations;
using DotnetIdentityTutorial.Services.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Testcontainers.PostgreSql;

namespace DotnetIdentityTutorial.Tests.Services;

/// <summary>
/// Exercises <see cref="IRbacService"/> directly against a real Testcontainers-provisioned
/// PostgreSQL instance, not through HTTP: every controller action introduced on this branch
/// carries an <c>[Authorize(Policy = "...")]</c> attribute that can't resolve until
/// feature/claims-and-authorization lands (see the deviation entry in CLAUDE.md), so exercising
/// the same behavior through <c>WebApplicationFactory</c> would only ever observe an
/// authorization failure, never the service logic itself.
///
/// One container is shared across every test in this class via <see cref="RbacServiceFixture"/>
/// (xUnit runs test methods within a class sequentially by default, so this is safe) rather than
/// spinning up a fresh Postgres container per fact - each test still creates its own
/// uniquely-named roles/permissions/users so tests never interfere with each other's state.
/// </summary>
public class RbacServiceTests : IClassFixture<RbacServiceFixture>
{
    private readonly RbacServiceFixture _fixture;

    public RbacServiceTests(RbacServiceFixture fixture)
    {
        _fixture = fixture;
    }

    private static string Unique(string prefix) => $"{prefix}_{Guid.NewGuid():N}".ToUpperInvariant();

    [Fact]
    public async Task CreatePermissionAsync_NewPermission_PersistsAndIsReturnedByGetPermissions()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var rbacService = scope.ServiceProvider.GetRequiredService<IRbacService>();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var resource = Unique("RES");

        var created = await rbacService.CreatePermissionAsync(new PermissionRequest(resource, "READ"));

        Assert.True(created.Id > 0);
        var all = await rbacService.GetPermissionsAsync();
        Assert.Contains(all, p => p.Id == created.Id && p.Resource == resource && p.Action == "READ");

        // CreatePermissionAsync calls IAuditService.LogAsync with the newly created permission's
        // own id as the entity id - feature/audit-logging's own checklist item, re-run against
        // feature/rbac's existing test rather than duplicated into a parallel test file.
        var auditLog = await dbContext.AuditLogs
            .SingleAsync(a => a.EntityType == nameof(Permission) && a.EntityId == created.Id.ToString());
        Assert.Equal("Create", auditLog.Action);
    }

    [Fact]
    public async Task CreatePermissionAsync_DuplicateResourceAction_ThrowsBusinessRuleException()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var rbacService = scope.ServiceProvider.GetRequiredService<IRbacService>();
        var resource = Unique("RES");
        await rbacService.CreatePermissionAsync(new PermissionRequest(resource, "READ"));

        await Assert.ThrowsAsync<BusinessRuleException>(
            () => rbacService.CreatePermissionAsync(new PermissionRequest(resource, "READ")));
    }

    [Fact]
    public async Task CreateRoleAsync_NewRole_PersistsWithNoPermissions()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var rbacService = scope.ServiceProvider.GetRequiredService<IRbacService>();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var roleName = Unique("ROLE");

        var created = await rbacService.CreateRoleAsync(new RoleRequest(roleName));

        Assert.True(created.Id > 0);
        Assert.Equal(roleName, created.Name);
        Assert.Empty(created.Permissions);

        var auditLog = await dbContext.AuditLogs
            .SingleAsync(a => a.EntityType == nameof(ApplicationRole) && a.EntityId == created.Id.ToString());
        Assert.Equal("Create", auditLog.Action);
    }

    [Fact]
    public async Task CreateRoleAsync_DuplicateName_ThrowsBusinessRuleException()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var rbacService = scope.ServiceProvider.GetRequiredService<IRbacService>();
        var roleName = Unique("ROLE");
        await rbacService.CreateRoleAsync(new RoleRequest(roleName));

        await Assert.ThrowsAsync<BusinessRuleException>(
            () => rbacService.CreateRoleAsync(new RoleRequest(roleName)));
    }

    [Fact]
    public async Task AssignPermissionToRoleAsync_CalledTwice_IsIdempotentAndPersistsOnlyOneRow()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var rbacService = scope.ServiceProvider.GetRequiredService<IRbacService>();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var role = await rbacService.CreateRoleAsync(new RoleRequest(Unique("ROLE")));
        var permission = await rbacService.CreatePermissionAsync(new PermissionRequest(Unique("RES"), "READ"));

        await rbacService.AssignPermissionToRoleAsync(role.Id, permission.Id);
        await rbacService.AssignPermissionToRoleAsync(role.Id, permission.Id);

        var count = await dbContext.RolePermissions
            .CountAsync(rp => rp.RoleId == role.Id && rp.PermissionId == permission.Id);
        Assert.Equal(1, count);

        var roleAfter = (await rbacService.GetRolesAsync()).Single(r => r.Id == role.Id);
        Assert.Contains(roleAfter.Permissions, p => p.Id == permission.Id);

        // AssignPermissionToRoleAsync logs unconditionally on every call, even when the
        // relationship already existed - the audit trail records that the operation was invoked
        // twice, which is a genuinely different fact from RolePermissions staying at one row
        // (asserted above). Idempotency is a property of the resulting state, not of how many
        // times the action was attempted.
        var auditLogs = await dbContext.AuditLogs
            .Where(a => a.Action == "AssignPermission" && a.EntityType == nameof(ApplicationRole) && a.EntityId == role.Id.ToString())
            .ToListAsync();
        Assert.Equal(2, auditLogs.Count);
    }

    [Fact]
    public async Task RemovePermissionFromRoleAsync_NotAssigned_IsNoOpAndDoesNotThrow()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var rbacService = scope.ServiceProvider.GetRequiredService<IRbacService>();
        var role = await rbacService.CreateRoleAsync(new RoleRequest(Unique("ROLE")));
        var permission = await rbacService.CreatePermissionAsync(new PermissionRequest(Unique("RES"), "READ"));

        // Never assigned in the first place - removal should be a silent no-op, not an error.
        var exception = await Record.ExceptionAsync(
            () => rbacService.RemovePermissionFromRoleAsync(role.Id, permission.Id));

        Assert.Null(exception);
    }

    [Fact]
    public async Task AssignPermissionToRoleAsync_ThenRemove_RemovesTheRow()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var rbacService = scope.ServiceProvider.GetRequiredService<IRbacService>();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var role = await rbacService.CreateRoleAsync(new RoleRequest(Unique("ROLE")));
        var permission = await rbacService.CreatePermissionAsync(new PermissionRequest(Unique("RES"), "READ"));
        await rbacService.AssignPermissionToRoleAsync(role.Id, permission.Id);

        await rbacService.RemovePermissionFromRoleAsync(role.Id, permission.Id);

        var exists = await dbContext.RolePermissions
            .AnyAsync(rp => rp.RoleId == role.Id && rp.PermissionId == permission.Id);
        Assert.False(exists);

        // SingleAsync itself is the assertion here: it throws if no matching row exists, and
        // would also throw if RemovePermissionFromRoleAsync's earlier unconditional
        // AssignPermission-then-RemovePermission calls somehow produced more than one.
        await dbContext.AuditLogs
            .SingleAsync(a => a.Action == "RemovePermission" && a.EntityType == nameof(ApplicationRole) && a.EntityId == role.Id.ToString());
    }

    [Fact]
    public async Task AssignPermissionToRoleAsync_UnknownRoleId_ThrowsResourceNotFoundException()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var rbacService = scope.ServiceProvider.GetRequiredService<IRbacService>();
        var permission = await rbacService.CreatePermissionAsync(new PermissionRequest(Unique("RES"), "READ"));

        await Assert.ThrowsAsync<ResourceNotFoundException>(
            () => rbacService.AssignPermissionToRoleAsync(-1, permission.Id));
    }

    [Fact]
    public async Task AssignPermissionToRoleAsync_UnknownPermissionId_ThrowsResourceNotFoundException()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var rbacService = scope.ServiceProvider.GetRequiredService<IRbacService>();
        var role = await rbacService.CreateRoleAsync(new RoleRequest(Unique("ROLE")));

        await Assert.ThrowsAsync<ResourceNotFoundException>(
            () => rbacService.AssignPermissionToRoleAsync(role.Id, -1));
    }

    [Fact]
    public async Task AssignRoleToUserAsync_CalledTwice_IsIdempotentAndUserIsInRoleOnce()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var rbacService = scope.ServiceProvider.GetRequiredService<IRbacService>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var role = await rbacService.CreateRoleAsync(new RoleRequest(Unique("ROLE")));
        var user = await CreateUserAsync(userManager);

        await rbacService.AssignRoleToUserAsync(user.Id, role.Id);
        await rbacService.AssignRoleToUserAsync(user.Id, role.Id);

        var roles = await userManager.GetRolesAsync(user);
        Assert.Single(roles, role.Name);

        // Same "logs every call, not just the ones that changed state" behavior as
        // AssignPermissionToRoleAsync above - two calls, two audit rows, one resulting role
        // membership.
        var auditLogs = await dbContext.AuditLogs
            .Where(a => a.Action == "AssignRole" && a.EntityType == "User" && a.EntityId == user.Id.ToString())
            .ToListAsync();
        Assert.Equal(2, auditLogs.Count);
    }

    [Fact]
    public async Task RemoveRoleFromUserAsync_NotAssigned_IsNoOpAndDoesNotThrow()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var rbacService = scope.ServiceProvider.GetRequiredService<IRbacService>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var role = await rbacService.CreateRoleAsync(new RoleRequest(Unique("ROLE")));
        var user = await CreateUserAsync(userManager);

        var exception = await Record.ExceptionAsync(
            () => rbacService.RemoveRoleFromUserAsync(user.Id, role.Id));

        Assert.Null(exception);
    }

    [Fact]
    public async Task AssignRoleToUserAsync_ThenRemove_UserNoLongerInRole()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var rbacService = scope.ServiceProvider.GetRequiredService<IRbacService>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var role = await rbacService.CreateRoleAsync(new RoleRequest(Unique("ROLE")));
        var user = await CreateUserAsync(userManager);
        await rbacService.AssignRoleToUserAsync(user.Id, role.Id);

        await rbacService.RemoveRoleFromUserAsync(user.Id, role.Id);

        var roles = await userManager.GetRolesAsync(user);
        Assert.Empty(roles);

        await dbContext.AuditLogs
            .SingleAsync(a => a.Action == "RemoveRole" && a.EntityType == "User" && a.EntityId == user.Id.ToString());
    }

    [Fact]
    public async Task AssignRoleToUserAsync_UnknownUserId_ThrowsResourceNotFoundException()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var rbacService = scope.ServiceProvider.GetRequiredService<IRbacService>();
        var role = await rbacService.CreateRoleAsync(new RoleRequest(Unique("ROLE")));

        await Assert.ThrowsAsync<ResourceNotFoundException>(
            () => rbacService.AssignRoleToUserAsync(-1, role.Id));
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
/// Shared Testcontainers PostgreSQL instance and DI container for <see cref="RbacServiceTests"/>.
/// Registers the same pieces <c>Program.cs</c> does for Identity/AppDbContext, plus
/// <see cref="IRbacService"/>/<see cref="IAuditService"/>, so the service under test runs against
/// the exact same schema a real deployment would use.
/// </summary>
public sealed class RbacServiceFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer _postgresContainer = new PostgreSqlBuilder("postgres:16")
        .WithDatabase("dotnet_identity_tutorial_rbac_test")
        .WithUsername("test")
        .WithPassword("test")
        .Build();

    public ServiceProvider ServiceProvider { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        await _postgresContainer.StartAsync();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(TimeProvider.System);

        // AuditService (now a real, AppDbContext-backed implementation as of
        // feature/audit-logging) needs IHttpContextAccessor to resolve an actor - there is no
        // real HTTP request in this service-layer test, so it resolves to a null actor, which is
        // the expected, documented behavior for a call with no ambient HttpContext.
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
        services.AddScoped<IRbacService, RbacService>();

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
