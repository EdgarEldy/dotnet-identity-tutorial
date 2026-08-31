using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;

namespace DotnetIdentityTutorial.RateLimiting;

/// <summary>
/// Named rate limiter policies, applied to individual actions via
/// <c>[EnableRateLimiting("...")]</c> rather than a single global limit for the whole API.
/// </summary>
public static class RateLimiterPolicies
{
    /// <summary>
    /// A fixed-window limit of 5 requests/minute per client IP, applied to
    /// <c>Auth/Register</c>, <c>Auth/Login</c>, and <c>Auth/ForgotPassword</c> (and, once
    /// feature/mfa lands, <c>Auth/VerifyTwoFactor</c>). Identity's own account lockout already
    /// protects a single account from repeated bad passwords; this protects the endpoint itself
    /// from a distributed attempt spread across many different accounts/emails from the same
    /// source, which per-account lockout alone would not catch.
    /// </summary>
    public const string Auth = "auth";

    public static void AddAuthPolicy(this RateLimiterOptions options)
    {
        options.AddPolicy(Auth, httpContext => RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
            }));
    }

    /// <summary>
    /// ASP.NET Core's own default for a rejected request is 503 Service Unavailable with an
    /// empty body - neither matches this project's conventions (a rate limit is a client-side
    /// concern, 429 Too Many Requests per RFC 6585, and every non-2xx response elsewhere is a
    /// ProblemDetails, produced through the same <see cref="IProblemDetailsService"/> the
    /// exception handler uses, not a bespoke shape).
    /// </summary>
    public static void ConfigureRejectionResponse(this RateLimiterOptions options)
    {
        options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        options.OnRejected = async (context, cancellationToken) =>
        {
            var problemDetailsService = context.HttpContext.RequestServices.GetRequiredService<IProblemDetailsService>();
            await problemDetailsService.TryWriteAsync(new ProblemDetailsContext
            {
                HttpContext = context.HttpContext,
                ProblemDetails = new ProblemDetails
                {
                    Status = StatusCodes.Status429TooManyRequests,
                    Title = "Too many requests.",
                    Detail = "Rate limit exceeded for this endpoint. Try again later.",
                    Type = "https://tools.ietf.org/html/rfc6585#section-4",
                },
            });
        };
    }
}
