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
///
/// Calls RoleManager directly rather than going through a Services/Implementations wrapper:
/// this is bootstrap code that runs once at startup, not something reachable from a request,
/// and it is tested directly against a real database (DbInitializerTests) rather than through
/// a mocked service interface, so the usual "no Identity manager outside Services/Implementations"
/// rule is deliberately not applied here. This is the one sanctioned exception, alongside
/// Program.cs's own AddIdentity/AddEntityFrameworkStores calls.
///
/// This also does not call IAuditService: that service does not exist until
/// feature/audit-logging, and startup seeding has no real "actor" performing the action in
/// the sense the audit trail is meant to capture. Revisit once that branch lands.
/// </summary>
public static class DbInitializer
{
    private const string AdminRoleName = "ADMIN";

    private static readonly string[] Roles = [AdminRoleName, "USER"];

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
            if (await roleManager.RoleExistsAsync(roleName))
            {
                continue;
            }

            var result = await roleManager.CreateAsync(new ApplicationRole { Name = roleName });
            if (!result.Succeeded)
            {
                // Unlike EF Core's SaveChangesAsync below, RoleManager.CreateAsync fails by
                // returning a result instead of throwing, an unchecked result here would let
                // seeding continue as if the role existed and fail confusingly later instead.
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                throw new InvalidOperationException($"Failed to seed role '{roleName}': {errors}");
            }
        }
    }

    private static async Task SeedPermissionsAsync(AppDbContext dbContext)
    {
        var existing = await dbContext.Permissions
            .Select(p => new { p.Resource, p.Action })
            .ToListAsync();
        var existingSet = existing.Select(e => (e.Resource, e.Action)).ToHashSet();

        var missing = BaselinePermissions
            .Where(bp => !existingSet.Contains(bp))
            .Select(bp => new Permission { Resource = bp.Resource, Action = bp.Action });

        dbContext.Permissions.AddRange(missing);
        await dbContext.SaveChangesAsync();
    }

    private static async Task AssignPermissionsToAdminAsync(AppDbContext dbContext)
    {
        var adminRole = await dbContext.Roles.SingleAsync(r => r.NormalizedName == AdminRoleName);
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
