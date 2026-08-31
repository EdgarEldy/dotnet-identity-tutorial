using DotnetIdentityTutorial.Identity;

namespace DotnetIdentityTutorial.Models;

/// <summary>
/// The many-to-many join between <see cref="ApplicationRole"/> and <see cref="Permission"/>.
/// No surrogate key: the composite primary key on (RoleId, PermissionId) is the natural key
/// for this relationship and is configured in
/// <see cref="Configurations.RolePermissionConfiguration"/>.
/// </summary>
public class RolePermission
{
    public int RoleId { get; set; }

    public ApplicationRole Role { get; set; } = null!;

    public int PermissionId { get; set; }

    public Permission Permission { get; set; } = null!;
}
