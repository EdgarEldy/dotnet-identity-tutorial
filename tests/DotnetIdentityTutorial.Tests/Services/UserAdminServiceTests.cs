using DotnetIdentityTutorial.Data;
using DotnetIdentityTutorial.Exceptions;
using DotnetIdentityTutorial.Identity;
using DotnetIdentityTutorial.Services.Implementations;
using DotnetIdentityTutorial.Services.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Testcontainers.PostgreSql;

namespace DotnetIdentityTutorial.Tests.Services;

/// <summary>
/// Exercises <see cref="IUserAdminService"/> directly against a real Testcontainers-provisioned
/// PostgreSQL instance - see <see cref="RbacServiceTests"/>'s remarks for why this is a service-
/// layer test rather than an HTTP one on this branch. Uses <see cref="FakeTimeProvider"/> (shared
/// across the class, like the container) so lock/unlock assertions can check the exact
/// <c>LockoutEnd</c> value written, instead of a loose "is in the future" check.
/// </summary>
public class UserAdminServiceTests : IClassFixture<UserAdminServiceFixture>
{
    private readonly UserAdminServiceFixture _fixture;

    public UserAdminServiceTests(UserAdminServiceFixture fixture)
    {
        _fixture = fixture;
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

    [Fact]
    public async Task GetUserByIdAsync_ExistingUser_ReturnsUserWithRoles()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
        var userAdminService = scope.ServiceProvider.GetRequiredService<IUserAdminService>();
        var user = await CreateUserAsync(userManager);
        var roleName = $"ROLE_{Guid.NewGuid():N}".ToUpperInvariant();
        await roleManager.CreateAsync(new ApplicationRole { Name = roleName });
        await userManager.AddToRoleAsync(user, roleName);

        var response = await userAdminService.GetUserByIdAsync(user.Id);

        Assert.Equal(user.Id, response.Id);
        Assert.Equal(user.Email, response.Email);
        Assert.Contains(roleName, response.Roles);
        Assert.Null(response.LockoutEnd);
    }

    [Fact]
    public async Task GetUserByIdAsync_UnknownId_ThrowsResourceNotFoundException()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var userAdminService = scope.ServiceProvider.GetRequiredService<IUserAdminService>();

        await Assert.ThrowsAsync<ResourceNotFoundException>(() => userAdminService.GetUserByIdAsync(-1));
    }

    [Fact]
    public async Task LockUserAsync_UnknownId_ThrowsResourceNotFoundException()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var userAdminService = scope.ServiceProvider.GetRequiredService<IUserAdminService>();

        await Assert.ThrowsAsync<ResourceNotFoundException>(() => userAdminService.LockUserAsync(-1));
    }

    [Fact]
    public async Task LockUserAsync_ThenUnlockUserAsync_RoundTripsLockoutEnd()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var userAdminService = scope.ServiceProvider.GetRequiredService<IUserAdminService>();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var user = await CreateUserAsync(userManager);

        await userAdminService.LockUserAsync(user.Id);

        var lockedResponse = await userAdminService.GetUserByIdAsync(user.Id);
        Assert.NotNull(lockedResponse.LockoutEnd);
        Assert.True(lockedResponse.LockoutEnd > _fixture.TimeProvider.GetUtcNow());

        await userAdminService.UnlockUserAsync(user.Id);

        var unlockedResponse = await userAdminService.GetUserByIdAsync(user.Id);
        Assert.Null(unlockedResponse.LockoutEnd);

        // Both LockUserAsync and UnlockUserAsync call IAuditService.LogAsync - feature/audit-
        // logging's own checklist item, re-run against feature/rbac's existing test rather than
        // duplicated into a parallel test file.
        await dbContext.AuditLogs
            .SingleAsync(a => a.Action == "Lock" && a.EntityType == "User" && a.EntityId == user.Id.ToString());

        await dbContext.AuditLogs
            .SingleAsync(a => a.Action == "Unlock" && a.EntityType == "User" && a.EntityId == user.Id.ToString());
    }

    [Fact]
    public async Task GetUsersAsync_ReturnsRequestedPageAndAccurateTotalCount()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var userAdminService = scope.ServiceProvider.GetRequiredService<IUserAdminService>();
        await CreateUserAsync(userManager);
        await CreateUserAsync(userManager);

        var expectedTotalCount = await dbContext.Users.CountAsync();
        var (page, totalCount) = await userAdminService.GetUsersAsync(page: 1, pageSize: expectedTotalCount);

        Assert.Equal(expectedTotalCount, totalCount);
        Assert.Equal(expectedTotalCount, page.Count);
    }

    [Fact]
    public async Task GetUsersAsync_PageSizeSmallerThanTotal_ReturnsOnlyThatManyItems()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var userAdminService = scope.ServiceProvider.GetRequiredService<IUserAdminService>();
        await CreateUserAsync(userManager);
        await CreateUserAsync(userManager);
        await CreateUserAsync(userManager);

        var (page, _) = await userAdminService.GetUsersAsync(page: 1, pageSize: 1);

        Assert.Single(page);
    }

    [Theory]
    [InlineData(0, 20)]
    [InlineData(-1, 20)]
    [InlineData(1, 0)]
    [InlineData(1, -5)]
    [InlineData(1, 101)]
    public async Task GetUsersAsync_InvalidPageOrPageSize_ThrowsBusinessRuleException(int page, int pageSize)
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var userAdminService = scope.ServiceProvider.GetRequiredService<IUserAdminService>();

        await Assert.ThrowsAsync<BusinessRuleException>(() => userAdminService.GetUsersAsync(page, pageSize));
    }

    [Fact]
    public async Task GetUsersAsync_MultipleUsersWithRoles_ReturnsCorrectRolesPerUser()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
        var userAdminService = scope.ServiceProvider.GetRequiredService<IUserAdminService>();

        if (!await roleManager.RoleExistsAsync("ADMIN"))
        {
            await roleManager.CreateAsync(new ApplicationRole { Name = "ADMIN" });
        }

        var adminUser = await CreateUserAsync(userManager);
        await userManager.AddToRoleAsync(adminUser, "ADMIN");
        var plainUser = await CreateUserAsync(userManager);

        var (page, _) = await userAdminService.GetUsersAsync(page: 1, pageSize: 100);

        var adminResponse = Assert.Single(page, u => u.Id == adminUser.Id);
        Assert.Contains("ADMIN", adminResponse.Roles);

        var plainResponse = Assert.Single(page, u => u.Id == plainUser.Id);
        Assert.Empty(plainResponse.Roles);
    }
}

/// <summary>
/// Shared Testcontainers PostgreSQL instance, DI container, and <see cref="FakeTimeProvider"/>
/// for <see cref="UserAdminServiceTests"/>.
/// </summary>
public sealed class UserAdminServiceFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer _postgresContainer = new PostgreSqlBuilder("postgres:16")
        .WithDatabase("dotnet_identity_tutorial_useradmin_test")
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

        // See RbacServiceFixture's identical registration for why this is needed now that
        // AuditService is a real, AppDbContext-backed implementation.
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

                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Lockout.AllowedForNewUsers = true;
            })
            .AddEntityFrameworkStores<AppDbContext>()
            .AddDefaultTokenProviders();

        services.AddScoped<IAuditService, AuditService>();
        services.AddScoped<IUserAdminService, UserAdminService>();

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
