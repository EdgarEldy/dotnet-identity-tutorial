namespace DotnetIdentityTutorial.Exceptions;

/// <summary>
/// Thrown when a request is well-formed but violates a business rule (e.g. a state
/// transition that isn't allowed). Mapped by <see cref="DotnetIdentityTutorial.ErrorHandling.GlobalExceptionHandler"/>
/// to a 422 Unprocessable Entity <c>ProblemDetails</c> response.
/// </summary>
public sealed class BusinessRuleException : Exception
{
    public BusinessRuleException(string message)
        : base(message)
    {
    }

    public BusinessRuleException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
