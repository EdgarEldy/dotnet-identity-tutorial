using DotnetIdentityTutorial.Services.Interfaces;

namespace DotnetIdentityTutorial.Services.Implementations;

/// <summary>
/// Tutorial-only implementation of <see cref="IEmailService"/>: instead of integrating a
/// real mail provider, it logs the link that would have been emailed. This keeps the
/// project self-contained while still exercising the same call sites
/// (<c>RegisterAsync</c>, <c>ForgotPasswordAsync</c>) a production implementation would use.
/// </summary>
public sealed class EmailService : IEmailService
{
    private readonly ILogger<EmailService> _logger;

    public EmailService(ILogger<EmailService> logger)
    {
        _logger = logger;
    }

    public Task SendConfirmationEmailAsync(string toEmail, string confirmationLink)
    {
        _logger.LogInformation("Confirmation email for {Email}: {ConfirmationLink}", toEmail, confirmationLink);
        return Task.CompletedTask;
    }

    public Task SendPasswordResetEmailAsync(string toEmail, string resetLink)
    {
        _logger.LogInformation("Password reset email for {Email}: {ResetLink}", toEmail, resetLink);
        return Task.CompletedTask;
    }
}
