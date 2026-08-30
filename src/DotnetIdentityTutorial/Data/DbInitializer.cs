using DotnetIdentityTutorial.Identity;
using DotnetIdentityTutorial.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace DotnetIdentityTutorial.Data;

/// <summary>
/// Startup seeding: default roles, the baseline permission set, and ADMIN's grant of every
/// one of those permissions. Runs on every application startup (see Program.cs) rather than
/// as a one-off script, so every step here is check-then-insert instead of relying on a
/// unique-constraint violation to make the operation idempotent - that way a duplicate row
/// never even gets attempted, and the seeding logic reads the same as any other idempotent
/// upsert instead of using an exception as control flow.
/// </summary>
public static class DbInitializer
{
    private static readonly string[] Roles = ["ADMIN", "USER"];

    private static readonly (string Resource, string Action)[] BaselinePermissions =
    [
        ("USER", "READ"),
        ("USER", "WRITE"),
        ("ROLE", "READ"),
        ("ROLE", "WRITE"),
        ("PERMISSION", "READ"),
        ("PERMISSION", "WRITE"),
        ("AUDIT", "READ"),
    ];

    public static async Task SeedAsync(IServiceProvider serviceProvider)
    {
        var roleManager = serviceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
        var dbContext = serviceProvider.GetRequiredService<AppDbContext>();

        await SeedRolesAsync(roleManager);
        await SeedPermissionsAsync(dbContext);
        await AssignPermissionsToAdminAsync(dbContext);
    }

    private static async Task SeedRolesAsync(RoleManager<ApplicationRole> roleManager)
    {
        foreach (var roleName in Roles)
        {
            if (!await roleManager.RoleExistsAsync(roleName))
            {
                await roleManager.CreateAsync(new ApplicationRole { Name = roleName });
            }
        }
    }

    private static async Task SeedPermissionsAsync(AppDbContext dbContext)
    {
        var existing = await dbContext.Permissions
            .Select(p => new { p.Resource, p.Action })
            .ToListAsync();

        var missing = BaselinePermissions
            .Where(bp => !existing.Any(e => e.Resource == bp.Resource && e.Action == bp.Action))
            .Select(bp => new Permission { Resource = bp.Resource, Action = bp.Action });

        dbContext.Permissions.AddRange(missing);
        await dbContext.SaveChangesAsync();
    }

    private static async Task AssignPermissionsToAdminAsync(AppDbContext dbContext)
    {
        var adminRole = await dbContext.Roles.SingleAsync(r => r.NormalizedName == "ADMIN");
        var allPermissionIds = await dbContext.Permissions.Select(p => p.Id).ToListAsync();

        var alreadyAssignedIds = await dbContext.RolePermissions
            .Where(rp => rp.RoleId == adminRole.Id)
            .Select(rp => rp.PermissionId)
            .ToListAsync();

        var missing = allPermissionIds
            .Except(alreadyAssignedIds)
            .Select(permissionId => new RolePermission { RoleId = adminRole.Id, PermissionId = permissionId });

        dbContext.RolePermissions.AddRange(missing);
        await dbContext.SaveChangesAsync();
    }
}
