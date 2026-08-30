namespace DotnetIdentityTutorial.Exceptions;

/// <summary>
/// Thrown when a requested resource does not exist. Mapped by <see cref="DotnetIdentityTutorial.ErrorHandling.GlobalExceptionHandler"/>
/// to a 404 Not Found <c>ProblemDetails</c> response.
/// </summary>
public sealed class ResourceNotFoundException : Exception
{
    public ResourceNotFoundException(string message)
        : base(message)
    {
    }

    public ResourceNotFoundException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
