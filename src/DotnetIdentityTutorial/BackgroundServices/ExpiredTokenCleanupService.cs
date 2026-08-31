using DotnetIdentityTutorial.Data;
using Microsoft.EntityFrameworkCore;

namespace DotnetIdentityTutorial.BackgroundServices;

/// <summary>
/// Housekeeping, not a security control: a revoked or expired <c>RefreshToken</c>/
/// <c>BlacklistedAccessToken</c> row is already rejected by <c>TokenService</c>/
/// <c>OnTokenValidated</c> regardless of whether the row still exists, revocation only marks a
/// row, it never removes it. Without this, both tables grow unbounded forever. Runs once
/// immediately on startup and then once a day for as long as the host is running, driven by the
/// injected <see cref="TimeProvider"/> (via <see cref="PeriodicTimer"/>'s <c>TimeProvider</c>
/// overload) rather than the system clock, so a test can advance a <c>FakeTimeProvider</c>
/// instead of waiting a real 24 hours.
/// </summary>
public sealed class ExpiredTokenCleanupService : BackgroundService
{
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromDays(1);

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<ExpiredTokenCleanupService> _logger;

    public ExpiredTokenCleanupService(
        IServiceScopeFactory scopeFactory,
        TimeProvider timeProvider,
        ILogger<ExpiredTokenCleanupService> logger)
    {
        _scopeFactory = scopeFactory;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(CleanupInterval, _timeProvider);

        do
        {
            await CleanupExpiredTokensAsync(stoppingToken);
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    private async Task CleanupExpiredTokensAsync(CancellationToken cancellationToken)
    {
        using var scope = _scopeFactory.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var now = _timeProvider.GetUtcNow();

        var deletedRefreshTokens = await dbContext.RefreshTokens
            .Where(rt => rt.ExpiresAt < now)
            .ExecuteDeleteAsync(cancellationToken);

        var deletedBlacklistedTokens = await dbContext.BlacklistedAccessTokens
            .Where(b => b.ExpiresAt < now)
            .ExecuteDeleteAsync(cancellationToken);

        _logger.LogInformation(
            "Expired token cleanup removed {RefreshTokenCount} refresh token(s) and {BlacklistedTokenCount} blacklisted access token(s).",
            deletedRefreshTokens,
            deletedBlacklistedTokens);
    }
}
