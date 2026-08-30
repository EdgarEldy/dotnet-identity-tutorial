using FluentValidation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace DotnetIdentityTutorial.Filters;

/// <summary>
/// Runs FluentValidation against every request DTO in the action's argument list before
/// the action executes, short-circuiting with a 400 <see cref="ValidationProblemDetails"/>
/// on failure. Registered globally (<c>options.Filters.Add&lt;ValidationFilter&gt;()</c>) so
/// no controller has to call it explicitly, and no manual <c>ModelState.IsValid</c> check
/// is ever needed.
///
/// If an action argument's type has no <see cref="IValidator{T}"/> registered in DI (there
/// simply isn't a validator for it, or it isn't a request DTO at all, e.g. a route id), this
/// filter no-ops for that argument rather than failing.
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
        foreach (var argument in context.ActionArguments.Values)
        {
            if (argument is null)
            {
                continue;
            }

            var validatorType = typeof(IValidator<>).MakeGenericType(argument.GetType());
            if (_serviceProvider.GetService(validatorType) is not IValidator validator)
            {
                // No validator registered for this argument's type - nothing to do.
                continue;
            }

            var validationContext = new ValidationContext<object>(argument);
            var result = await validator.ValidateAsync(validationContext, context.HttpContext.RequestAborted);

            if (!result.IsValid)
            {
                var modelState = new Microsoft.AspNetCore.Mvc.ModelBinding.ModelStateDictionary();
                foreach (var error in result.Errors)
                {
                    modelState.AddModelError(error.PropertyName, error.ErrorMessage);
                }

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
