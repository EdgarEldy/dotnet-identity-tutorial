using System.Text.Json;
using DotnetIdentityTutorial.ErrorHandling;
using DotnetIdentityTutorial.Exceptions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace DotnetIdentityTutorial.Tests.ErrorHandling;

/// <summary>
/// Exercises <see cref="GlobalExceptionHandler"/> against a real <see cref="IProblemDetailsService"/>
/// (registered via the same <c>AddProblemDetails()</c> call <c>Program.cs</c> makes), so the
/// assertions cover the actual status code and JSON body written to the response, not a mocked
/// stand-in for that pipeline.
/// </summary>
public class GlobalExceptionHandlerTests
{
    private static (GlobalExceptionHandler Handler, DefaultHttpContext HttpContext) CreateHandler()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddProblemDetails();
        var serviceProvider = services.BuildServiceProvider();

        var problemDetailsService = serviceProvider.GetRequiredService<IProblemDetailsService>();
        var handler = new GlobalExceptionHandler(problemDetailsService, NullLogger<GlobalExceptionHandler>.Instance);

        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider,
            Response = { Body = new MemoryStream() },
        };
        httpContext.Request.Method = "GET";
        httpContext.Request.Path = "/api/v1/Test";

        return (handler, httpContext);
    }

    private static async Task<ProblemDetails> ReadProblemDetailsAsync(DefaultHttpContext httpContext)
    {
        httpContext.Response.Body.Position = 0;
        using var reader = new StreamReader(httpContext.Response.Body);
        var json = await reader.ReadToEndAsync();
        var problemDetails = JsonSerializer.Deserialize<ProblemDetails>(json, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
        });
        Assert.NotNull(problemDetails);
        return problemDetails!;
    }

    [Fact]
    public async Task TryHandleAsync_ResourceNotFoundException_Returns404()
    {
        var (handler, httpContext) = CreateHandler();
        var exception = new ResourceNotFoundException("User 42 was not found.");

        var handled = await handler.TryHandleAsync(httpContext, exception, CancellationToken.None);

        Assert.True(handled);
        Assert.Equal(StatusCodes.Status404NotFound, httpContext.Response.StatusCode);

        var problemDetails = await ReadProblemDetailsAsync(httpContext);
        Assert.Equal(StatusCodes.Status404NotFound, problemDetails.Status);
        Assert.Equal("Resource not found", problemDetails.Title);
        Assert.Equal("User 42 was not found.", problemDetails.Detail);
    }

    [Fact]
    public async Task TryHandleAsync_BusinessRuleException_Returns422()
    {
        var (handler, httpContext) = CreateHandler();
        var exception = new BusinessRuleException("A role cannot be assigned to a locked user.");

        var handled = await handler.TryHandleAsync(httpContext, exception, CancellationToken.None);

        Assert.True(handled);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, httpContext.Response.StatusCode);

        var problemDetails = await ReadProblemDetailsAsync(httpContext);
        Assert.Equal(StatusCodes.Status422UnprocessableEntity, problemDetails.Status);
        Assert.Equal("Business rule violation", problemDetails.Title);
        Assert.Equal("A role cannot be assigned to a locked user.", problemDetails.Detail);
    }

    [Fact]
    public async Task TryHandleAsync_UnmappedException_Returns500WithGenericDetail()
    {
        var (handler, httpContext) = CreateHandler();
        const string sensitiveMessage = "Connection string password authentication failed for user 'app'.";
        var exception = new InvalidOperationException(sensitiveMessage);

        var handled = await handler.TryHandleAsync(httpContext, exception, CancellationToken.None);

        Assert.True(handled);
        Assert.Equal(StatusCodes.Status500InternalServerError, httpContext.Response.StatusCode);

        var problemDetails = await ReadProblemDetailsAsync(httpContext);
        Assert.Equal(StatusCodes.Status500InternalServerError, problemDetails.Status);
        Assert.Equal("An unexpected error occurred", problemDetails.Title);

        // Deliberate security property: the real exception message must never reach the
        // client for an unmapped (500) exception, only the generic detail below. The full
        // exception is still logged server-side by GlobalExceptionHandler, just not returned.
        Assert.Equal("An unexpected error occurred. Please try again later.", problemDetails.Detail);
        Assert.DoesNotContain(sensitiveMessage, problemDetails.Detail);
    }
}
