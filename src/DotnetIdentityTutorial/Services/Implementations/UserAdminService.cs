using DotnetIdentityTutorial.Dtos.User;
using DotnetIdentityTutorial.Exceptions;
using DotnetIdentityTutorial.Identity;
using DotnetIdentityTutorial.Services.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace DotnetIdentityTutorial.Services.Implementations;

/// <summary>
/// The one place allowed to call <c>UserManager&lt;ApplicationUser&gt;</c> directly for user
/// administration - listing, detail, and lock/unlock. Lock/unlock go through
/// <c>SetLockoutEndDateAsync</c> against Identity's own <c>LockoutEnd</c> column, not a custom
/// "IsLocked" flag, matching how the README describes account lockout being handled everywhere
/// else in this project. The lockout timestamp is always read from the injected
/// <see cref="TimeProvider"/>, never <c>DateTime.UtcNow</c>, so tests can control it precisely
/// and this stays consistent with every other expiry/timestamp computation in the project.
/// </summary>
public sealed class UserAdminService : IUserAdminService
{
    // "Effectively indefinite until an explicit Unlock", not DateTimeOffset.MaxValue (some
    // database column types reject a value that extreme) - 100 years from "now" per
    // TimeProvider is far enough out that it never expires on its own in practice.
    private static readonly TimeSpan LockDuration = TimeSpan.FromDays(365 * 100);

    private readonly UserManager<ApplicationUser> _userManager;
    private readonly TimeProvider _timeProvider;
    private readonly IAuditService _auditService;

    public UserAdminService(UserManager<ApplicationUser> userManager, TimeProvider timeProvider, IAuditService auditService)
    {
        _userManager = userManager;
        _timeProvider = timeProvider;
        _auditService = auditService;
    }

    public async Task<(IReadOnlyList<UserResponse> Users, int TotalCount)> GetUsersAsync(int page, int pageSize, CancellationToken cancellationToken = default)
    {
        var totalCount = await _userManager.Users.CountAsync(cancellationToken);

        var users = await _userManager.Users
            .OrderBy(u => u.Id)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(cancellationToken);

        var responses = new List<UserResponse>(users.Count);
        foreach (var user in users)
        {
            responses.Add(await MapAsync(user));
        }

        return (responses, totalCount);
    }

    public async Task<UserResponse> GetUserByIdAsync(int userId, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString())
            ?? throw new ResourceNotFoundException($"User {userId} was not found.");

        return await MapAsync(user);
    }

    public async Task LockUserAsync(int userId, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString())
            ?? throw new ResourceNotFoundException($"User {userId} was not found.");

        if (!user.LockoutEnabled)
        {
            await _userManager.SetLockoutEnabledAsync(user, true);
        }

        var lockoutEnd = _timeProvider.GetUtcNow().Add(LockDuration);
        var result = await _userManager.SetLockoutEndDateAsync(user, lockoutEnd);
        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            throw new BusinessRuleException($"Failed to lock user {userId}: {errors}");
        }

        await _auditService.LogAsync("Lock", "User", userId.ToString(), new { LockoutEnd = lockoutEnd });
    }

    public async Task UnlockUserAsync(int userId, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString())
            ?? throw new ResourceNotFoundException($"User {userId} was not found.");

        var result = await _userManager.SetLockoutEndDateAsync(user, null);
        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            throw new BusinessRuleException($"Failed to unlock user {userId}: {errors}");
        }

        // Clearing LockoutEnd alone doesn't reset the failed-attempt counter Identity uses to
        // decide whether to re-lock the account on the next bad password; an admin unlock should
        // give the user a clean slate, not one bad attempt away from being auto-locked again.
        await _userManager.ResetAccessFailedCountAsync(user);

        await _auditService.LogAsync("Unlock", "User", userId.ToString(), null);
    }

    private async Task<UserResponse> MapAsync(ApplicationUser user)
    {
        var roles = await _userManager.GetRolesAsync(user);
        return new UserResponse(
            user.Id,
            user.Email ?? string.Empty,
            user.FirstName,
            user.LastName,
            roles.ToList(),
            user.LockoutEnd);
    }
}
