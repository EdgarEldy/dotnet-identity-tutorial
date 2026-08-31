using System.Security.Claims;
using DotnetIdentityTutorial.Authorization;
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
public sealed class ApplicationUserClaimsPrincipalFactory : UserClaimsPrincipalFactory<ApplicationUser, ApplicationRole>
{
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

        // Rides the RolePermission.Permission navigation property (already configured in
        // RolePermissionConfiguration) rather than re-deriving the join from raw DbSets, one
        // round trip regardless of how many roles the user has.
        var permissions = await _dbContext.RolePermissions
            .Where(rp => _dbContext.UserRoles.Any(ur => ur.UserId == user.Id && ur.RoleId == rp.RoleId))
            .Select(rp => rp.Permission.Resource + ":" + rp.Permission.Action)
            .Distinct()
            .ToListAsync();

        foreach (var permission in permissions)
        {
            identity.AddClaim(new Claim(PermissionRequirement.ClaimType, permission));
        }

        return identity;
    }
}
