using DotnetIdentityTutorial.Dtos.User;

namespace DotnetIdentityTutorial.Services.Interfaces;

/// <summary>
/// Wraps <c>UserManager&lt;ApplicationUser&gt;</c> for the user-administration half of this
/// branch: paginated listing, detail (including roles), and lock/unlock. Lockout uses Identity's
/// own <c>LockoutEnd</c> column rather than a custom boolean flag - see the README's "Design
/// decisions around Identity's built-in mechanisms".
/// </summary>
public interface IUserAdminService
{
    Task<(IReadOnlyList<UserResponse> Users, int TotalCount)> GetUsersAsync(int page, int pageSize, CancellationToken cancellationToken = default);

    Task<UserResponse> GetUserByIdAsync(int userId, CancellationToken cancellationToken = default);

    Task LockUserAsync(int userId, CancellationToken cancellationToken = default);

    Task UnlockUserAsync(int userId, CancellationToken cancellationToken = default);
}
