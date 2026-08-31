using System.Security.Claims;
using DotnetIdentityTutorial.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace DotnetIdentityTutorial.Identity;

/// <summary>
/// Resolves this project's fine-grained permissions into claims once, at sign-in time,
/// instead of re-querying RolePermission on every authorized request - see the README's
/// "Claims-based authorization" design section for the trade-off this implies (a permission
/// change on a role doesn't take effect for a user already holding a token until it's
/// refreshed). Registered in place of Identity's default factory via
/// <c>AddClaimsPrincipalFactory&lt;ApplicationUserClaimsPrincipalFactory&gt;()</c> in
/// Program.cs, so every call to <c>SignInManager</c>/<c>UserManager</c> that builds a
/// <see cref="ClaimsPrincipal"/> for a user goes through this instead of the base class.
/// </summary>
public class ApplicationUserClaimsPrincipalFactory : UserClaimsPrincipalFactory<ApplicationUser, ApplicationRole>
{
    private const string PermissionClaimType = "permission";

    private readonly AppDbContext _dbContext;

    public ApplicationUserClaimsPrincipalFactory(
        UserManager<ApplicationUser> userManager,
        RoleManager<ApplicationRole> roleManager,
        IOptions<IdentityOptions> optionsAccessor,
        AppDbContext dbContext)
        : base(userManager, roleManager, optionsAccessor)
    {
        _dbContext = dbContext;
    }

    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(ApplicationUser user)
    {
        var identity = await base.GenerateClaimsAsync(user);

        // A single join from AspNetUserRoles through RolePermissions to Permissions for this
        // user's current role ids, rather than looping over each role name and querying per
        // role - one round trip regardless of how many roles the user has.
        var permissions = await (
            from userRole in _dbContext.UserRoles
            join rolePermission in _dbContext.RolePermissions on userRole.RoleId equals rolePermission.RoleId
            join permission in _dbContext.Permissions on rolePermission.PermissionId equals permission.Id
            where userRole.UserId == user.Id
            select permission.Resource + ":" + permission.Action)
            .Distinct()
            .ToListAsync();

        foreach (var permission in permissions)
        {
            identity.AddClaim(new Claim(PermissionClaimType, permission));
        }

        return identity;
    }
}
