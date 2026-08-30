using FluentValidation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace DotnetIdentityTutorial.Filters;

/// <summary>
/// Runs FluentValidation against every request DTO in the action's parameter list before
/// the action executes, short-circuiting with a 400 <see cref="ValidationProblemDetails"/>
/// on failure. Registered globally (<c>options.Filters.Add&lt;ValidationFilter&gt;()</c>) so
/// no controller has to call it explicitly, and no manual <c>ModelState.IsValid</c> check
/// is ever needed.
///
/// Iterates <c>context.ActionDescriptor.Parameters</c> (the action's declared parameter
/// types) rather than <c>context.ActionArguments.Values</c> (the bound runtime values): a
/// parameter that failed to bind at all comes through as a null argument, and its declared
/// type is only recoverable from the descriptor, not from a null value's nonexistent
/// runtime type. If a parameter's declared type has no <see cref="IValidator{T}"/>
/// registered in DI (there simply isn't a validator for it, or it isn't a request DTO at
/// all, e.g. a route id), this filter no-ops for that parameter rather than failing.
/// </summary>
public sealed class ValidationFilter : IAsyncActionFilter
{
    private readonly IServiceProvider _serviceProvider;

    public ValidationFilter(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        foreach (var parameter in context.ActionDescriptor.Parameters)
        {
            var validatorType = typeof(IValidator<>).MakeGenericType(parameter.ParameterType);
            if (_serviceProvider.GetService(validatorType) is not IValidator validator)
            {
                // No validator registered for this parameter's declared type - nothing to do.
                continue;
            }

            context.ActionArguments.TryGetValue(parameter.Name, out var argument);

            var modelState = new ModelStateDictionary();
            if (argument is null)
            {
                // A validator exists for this parameter's type, but nothing bound to it (an
                // empty body, for example). That is itself a validation failure, not
                // something to let through and risk a NullReferenceException later.
                modelState.AddModelError(parameter.Name, $"{parameter.Name} is required.");
            }
            else
            {
                var validationContext = new ValidationContext<object>(argument);
                var result = await validator.ValidateAsync(validationContext, context.HttpContext.RequestAborted);
                foreach (var error in result.Errors)
                {
                    modelState.AddModelError(error.PropertyName, error.ErrorMessage);
                }
            }

            if (!modelState.IsValid)
            {
                context.Result = new BadRequestObjectResult(new ValidationProblemDetails(modelState)
                {
                    Status = StatusCodes.Status400BadRequest,
                    Title = "One or more validation errors occurred.",
                });
                return;
            }
        }

        await next();
    }
}
