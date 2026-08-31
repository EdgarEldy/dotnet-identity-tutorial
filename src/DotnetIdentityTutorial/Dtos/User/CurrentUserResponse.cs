namespace DotnetIdentityTutorial.Dtos.User;

/// <summary>
/// The shape returned by <c>GET /api/v1/Auth/Me</c>: the caller's own profile, roles, and
/// resolved "RESOURCE:ACTION" permissions. A dedicated type rather than reusing
/// <see cref="UserResponse"/> (the admin-facing shape from feature/rbac) since this one also
/// carries <see cref="Permissions"/> and is read for the caller themselves, not looked up by an
/// admin - <see cref="Permissions"/> is read directly from the caller's own JWT
/// "permission" claims (see <c>Authorization.PermissionRequirement.ClaimType</c>), not
/// re-queried from the database, since that's the whole point of baking them into the token at
/// sign-in.
/// </summary>
public sealed record CurrentUserResponse(
    int Id,
    string Email,
    string FirstName,
    string LastName,
    IReadOnlyList<string> Roles,
    IReadOnlyList<string> Permissions);
