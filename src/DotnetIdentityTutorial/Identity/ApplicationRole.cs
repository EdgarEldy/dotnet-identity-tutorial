using DotnetIdentityTutorial.Models;
using Microsoft.AspNetCore.Identity;

namespace DotnetIdentityTutorial.Identity;

/// <summary>
/// Used essentially as-is: this project's roles (<c>ADMIN</c>, <c>USER</c>) don't need
/// any column beyond what <see cref="IdentityRole{TKey}"/> already provides.
/// </summary>
public class ApplicationRole : IdentityRole<int>
{
    public ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
}
