namespace DotnetIdentityTutorial.Services.Interfaces;

/// <summary>
/// Sends the account-security emails this project needs (confirmation, password reset).
/// This is a project-defined contract, distinct from Identity's own
/// <c>IEmailSender&lt;TUser&gt;</c> extension point (relevant only to <c>MapIdentityApi</c>
/// or the scaffolded Identity UI, neither of which this project uses - <c>AuthController</c>
/// calls <c>UserManager</c>'s token methods directly and hands the resulting link to this
/// service instead).
/// </summary>
public interface IEmailService
{
    Task SendConfirmationEmailAsync(string toEmail, string confirmationLink);

    Task SendPasswordResetEmailAsync(string toEmail, string resetLink);
}
