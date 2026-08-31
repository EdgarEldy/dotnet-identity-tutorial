using DotnetIdentityTutorial.Services.Interfaces;

namespace DotnetIdentityTutorial.Tests.TestInfrastructure;

/// <summary>
/// Test-only stand-in for <see cref="IEmailService"/>. The real <c>EmailService</c> only logs
/// the confirmation/reset link (see its own remarks) - there is no inbox an end-to-end test could
/// read from, so this records the last link of each kind instead, letting a test extract the
/// real <c>userId</c>/<c>token</c> pair and drive <c>ConfirmEmail</c>/<c>ResetPassword</c>
/// through the actual HTTP pipeline rather than faking the token itself. Sequential test
/// execution per <see cref="AuthWebApplicationFactory"/> instance (one factory/container per
/// test class below) means thread-safety here is not a concern.
/// </summary>
public sealed class FakeEmailService : IEmailService
{
    public string? LastConfirmationLink { get; private set; }

    public string? LastResetLink { get; private set; }

    public Task SendConfirmationEmailAsync(string toEmail, string confirmationLink)
    {
        LastConfirmationLink = confirmationLink;
        return Task.CompletedTask;
    }

    public Task SendPasswordResetEmailAsync(string toEmail, string resetLink)
    {
        LastResetLink = resetLink;
        return Task.CompletedTask;
    }
}
