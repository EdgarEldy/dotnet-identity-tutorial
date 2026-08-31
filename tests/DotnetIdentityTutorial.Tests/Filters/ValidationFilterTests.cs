using DotnetIdentityTutorial.Filters;
using FluentValidation;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace DotnetIdentityTutorial.Tests.Filters;

/// <summary>
/// Exercises <see cref="ValidationFilter"/> in isolation, with a throwaway request-shaped class
/// and validator defined below since no real request DTO exists on this branch yet. Later
/// branches introducing actual DTOs/validators are expected to be covered end to end through
/// <c>WebApplicationFactory</c>, not by expanding this file.
/// </summary>
public class ValidationFilterTests
{
    private sealed record TestRequest(string Name);

    private sealed class TestRequestValidator : AbstractValidator<TestRequest>
    {
        public TestRequestValidator()
        {
            RuleFor(x => x.Name).NotEmpty().WithMessage("Name is required.");
        }
    }

    private sealed class UnvalidatedArgument
    {
        public string Value { get; init; } = string.Empty;
    }

    private static ActionExecutingContext CreateContext(
        IServiceProvider serviceProvider,
        (string Name, Type Type)[] parameters,
        IDictionary<string, object?> actionArguments)
    {
        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider,
        };

        var actionDescriptor = new ControllerActionDescriptor
        {
            Parameters = parameters
                .Select(p => (ParameterDescriptor)new ControllerParameterDescriptor
                {
                    Name = p.Name,
                    ParameterType = p.Type,
                })
                .ToList(),
        };

        var actionContext = new ActionContext(httpContext, new RouteData(), actionDescriptor);

        return new ActionExecutingContext(
            actionContext,
            new List<IFilterMetadata>(),
            actionArguments,
            controller: new object());
    }

    private static IServiceProvider BuildServiceProvider(bool registerValidator)
    {
        var services = new ServiceCollection();
        if (registerValidator)
        {
            services.AddScoped<IValidator<TestRequest>, TestRequestValidator>();
        }

        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task OnActionExecutionAsync_NoValidatorRegisteredForParameterType_CallsNextAndDoesNotSetResult()
    {
        var serviceProvider = BuildServiceProvider(registerValidator: false);
        var argument = new UnvalidatedArgument { Value = "anything" };
        var context = CreateContext(
            serviceProvider,
            [("arg", typeof(UnvalidatedArgument))],
            new Dictionary<string, object?> { ["arg"] = argument });
        var filter = new ValidationFilter(serviceProvider);

        var nextCalled = false;
        Task<ActionExecutedContext> Next()
        {
            nextCalled = true;
            return Task.FromResult(new ActionExecutedContext(context, context.Filters, context.Controller));
        }

        await filter.OnActionExecutionAsync(context, Next);

        Assert.True(nextCalled);
        Assert.Null(context.Result);
    }

    [Fact]
    public async Task OnActionExecutionAsync_ParameterBoundToNullWithRegisteredValidator_SetsBadRequestAndDoesNotCallNext()
    {
        var serviceProvider = BuildServiceProvider(registerValidator: true);
        var context = CreateContext(
            serviceProvider,
            [("request", typeof(TestRequest))],
            new Dictionary<string, object?> { ["request"] = null });
        var filter = new ValidationFilter(serviceProvider);

        var nextCalled = false;
        Task<ActionExecutedContext> Next()
        {
            nextCalled = true;
            return Task.FromResult(new ActionExecutedContext(context, context.Filters, context.Controller));
        }

        await filter.OnActionExecutionAsync(context, Next);

        Assert.False(nextCalled);
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(context.Result);
        var problemDetails = Assert.IsType<ValidationProblemDetails>(badRequestResult.Value);
        Assert.Equal(StatusCodes.Status400BadRequest, problemDetails.Status);
        Assert.True(problemDetails.Errors.ContainsKey("request"));
    }

    [Fact]
    public async Task OnActionExecutionAsync_RegisteredValidatorFails_SetsBadRequestValidationProblemDetailsAndDoesNotCallNext()
    {
        var serviceProvider = BuildServiceProvider(registerValidator: true);
        var argument = new TestRequest(string.Empty);
        var context = CreateContext(
            serviceProvider,
            [("request", typeof(TestRequest))],
            new Dictionary<string, object?> { ["request"] = argument });
        var filter = new ValidationFilter(serviceProvider);

        var nextCalled = false;
        Task<ActionExecutedContext> Next()
        {
            nextCalled = true;
            return Task.FromResult(new ActionExecutedContext(context, context.Filters, context.Controller));
        }

        await filter.OnActionExecutionAsync(context, Next);

        Assert.False(nextCalled);
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(context.Result);
        var problemDetails = Assert.IsType<ValidationProblemDetails>(badRequestResult.Value);

        Assert.Equal(StatusCodes.Status400BadRequest, problemDetails.Status);
        Assert.True(problemDetails.Errors.ContainsKey(nameof(TestRequest.Name)));
        Assert.Contains("Name is required.", problemDetails.Errors[nameof(TestRequest.Name)]);
    }

    [Fact]
    public async Task OnActionExecutionAsync_RegisteredValidatorPasses_CallsNextAndDoesNotSetResult()
    {
        var serviceProvider = BuildServiceProvider(registerValidator: true);
        var argument = new TestRequest("Ada Lovelace");
        var context = CreateContext(
            serviceProvider,
            [("request", typeof(TestRequest))],
            new Dictionary<string, object?> { ["request"] = argument });
        var filter = new ValidationFilter(serviceProvider);

        var nextCalled = false;
        Task<ActionExecutedContext> Next()
        {
            nextCalled = true;
            return Task.FromResult(new ActionExecutedContext(context, context.Filters, context.Controller));
        }

        await filter.OnActionExecutionAsync(context, Next);

        Assert.True(nextCalled);
        Assert.Null(context.Result);
    }
}
