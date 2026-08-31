using System.Globalization;

namespace DotnetIdentityTutorial.Extensions;

/// <summary>
/// Header-based pagination metadata, used by paginated list endpoints instead of a body
/// wrapper - see "Success responses and error responses" in the README. Sets
/// <c>X-Total-Count</c> and a standard <c>Link</c> header (RFC 8288) carrying <c>next</c>/
/// <c>prev</c> relations, while the response body stays the plain collection.
/// </summary>
public static class HttpResponseExtensions
{
    public const string TotalCountHeaderName = "X-Total-Count";
    public const string LinkHeaderName = "Link";

    /// <summary>
    /// Sets the <c>X-Total-Count</c> header and, when provided, a <c>Link</c> header with
    /// <c>rel="next"</c> and/or <c>rel="prev"</c> entries.
    /// </summary>
    public static void SetPaginationHeaders(this HttpResponse response, int totalCount, string? nextLink, string? prevLink)
    {
        response.Headers[TotalCountHeaderName] = totalCount.ToString(CultureInfo.InvariantCulture);

        var links = new List<string>();
        if (!string.IsNullOrEmpty(nextLink))
        {
            links.Add($"<{nextLink}>; rel=\"next\"");
        }

        if (!string.IsNullOrEmpty(prevLink))
        {
            links.Add($"<{prevLink}>; rel=\"prev\"");
        }

        if (links.Count > 0)
        {
            response.Headers[LinkHeaderName] = string.Join(", ", links);
        }
    }
}
