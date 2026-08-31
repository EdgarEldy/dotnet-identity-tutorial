using DotnetIdentityTutorial.Data;
using DotnetIdentityTutorial.Identity;
using DotnetIdentityTutorial.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Testcontainers.PostgreSql;

namespace DotnetIdentityTutorial.Tests.Authorization;

/// <summary>
/// Exercises <see cref="ApplicationUserClaimsPrincipalFactory"/> against a real
/// Testcontainers-provisioned PostgreSQL instance, the same pattern as
/// <c>RbacServiceTests</c>/<c>DbInitializerTests</c>: the behavior under test is a real EF Core
/// join across AspNetUserRoles/RolePermissions/Permissions, which an in-memory provider or a
/// mock wouldn't meaningfully verify.
/// </summary>
public class ApplicationUserClaimsPrincipalFactoryTests : IClassFixture<ClaimsPrincipalFactoryFixture>
{
    private readonly ClaimsPrincipalFactoryFixture _fixture;

    public ApplicationUserClaimsPrincipalFactoryTests(ClaimsPrincipalFactoryFixture fixture)
    {
        _fixture = fixture;
    }

    private static string Unique(string prefix) => $"{prefix}_{Guid.NewGuid():N}".ToUpperInvariant();

    [Fact]
    public async Task CreateAsync_UserWithTwoRolesGrantingOverlappingPermission_PermissionClaimAppearsExactlyOnce()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var services = scope.ServiceProvider;
        var dbContext = services.GetRequiredService<AppDbContext>();
        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = services.GetRequiredService<RoleManager<ApplicationRole>>();
        var factory = services.GetRequiredService<IUserClaimsPrincipalFactory<ApplicationUser>>();

        var sharedPermission = new Permission { Resource = Unique("RES"), Action = "READ" };
        dbContext.Permissions.Add(sharedPermission);
        await dbContext.SaveChangesAsync();

        var roleA = new ApplicationRole { Name = Unique("ROLE_A") };
        var roleB = new ApplicationRole { Name = Unique("ROLE_B") };
        await roleManager.CreateAsync(roleA);
        await roleManager.CreateAsync(roleB);

        dbContext.RolePermissions.Add(new RolePermission { RoleId = roleA.Id, PermissionId = sharedPermission.Id });
        dbContext.RolePermissions.Add(new RolePermission { RoleId = roleB.Id, PermissionId = sharedPermission.Id });
        await dbContext.SaveChangesAsync();

        var user = await CreateUserAsync(userManager);
        await userManager.AddToRoleAsync(user, roleA.Name!);
        await userManager.AddToRoleAsync(user, roleB.Name!);

        var principal = await factory.CreateAsync(user);

        var expectedPermission = $"{sharedPermission.Resource}:{sharedPermission.Action}";
        var permissionClaims = principal.Claims
            .Where(c => c.Type == "permission" && c.Value == expectedPermission)
            .ToList();
        Assert.Single(permissionClaims);
    }

    [Fact]
    public async Task CreateAsync_UserWithNoRoles_HasZeroPermissionClaims()
    {
        using var scope = _fixture.ServiceProvider.CreateScope();
        var services = scope.ServiceProvider;
        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
        var factory = services.GetRequiredService<IUserClaimsPrincipalFactory<ApplicationUser>>();

        var user = await CreateUserAsync(userManager);

        var principal = await factory.CreateAsync(user);

        Assert.DoesNotContain(principal.Claims, c => c.Type == "permission");
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
/// Shared Testcontainers PostgreSQL instance and DI container for
/// <see cref="ApplicationUserClaimsPrincipalFactoryTests"/>. Registers the same
/// <c>AddClaimsPrincipalFactory&lt;ApplicationUserClaimsPrincipalFactory&gt;()</c> wiring
/// Program.cs does, so the factory is resolved through DI exactly the way a real sign-in would.
/// </summary>
public sealed class ClaimsPrincipalFactoryFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer _postgresContainer = new PostgreSqlBuilder("postgres:16")
        .WithDatabase("dotnet_identity_tutorial_claims_test")
        .WithUsername("test")
        .WithPassword("test")
        .Build();

    public ServiceProvider ServiceProvider { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        await _postgresContainer.StartAsync();

        var services = new ServiceCollection();
        services.AddLogging();

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
            .AddDefaultTokenProviders()
            .AddClaimsPrincipalFactory<ApplicationUserClaimsPrincipalFactory>();

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
