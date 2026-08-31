namespace DotnetIdentityTutorial.Dtos.User;

/// <summary>
/// The shape returned by <c>GET /api/v1/Users</c> and <c>GET /api/v1/Users/{id}</c>.
/// <see cref="LockoutEnd"/> is exposed as-is (nullable) rather than as a derived boolean, so a
/// caller can tell not just whether the account is currently locked but until when.
/// </summary>
public record UserResponse(
    int Id,
    string Email,
    string FirstName,
    string LastName,
    IReadOnlyList<string> Roles,
    DateTimeOffset? LockoutEnd);
