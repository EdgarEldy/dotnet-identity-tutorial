using Microsoft.AspNetCore.Identity;

namespace DotnetIdentityTutorial.Identity;

/// <summary>
/// Extends Identity's own <see cref="IdentityUser{TKey}"/> with the extra columns this
/// project needs. Everything else (email, password hash, security stamp, lockout state,
/// two-factor flag, ...) is already provided by the base class and backed by Identity's
/// own <c>AspNetUsers</c> table.
/// </summary>
public class ApplicationUser : IdentityUser<int>
{
    public required string FirstName { get; set; }

    public required string LastName { get; set; }
}
