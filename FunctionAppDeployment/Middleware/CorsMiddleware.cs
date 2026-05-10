using Microsoft.AspNetCore.Http;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Middleware;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FunctionAppDeployment.Middleware
{
    public class CorsOptions
    {
        // Allowed origins (e.g., "https://www.google.com")
        // Use "*" to allow all origins (not recommended for production)
        public List<string> AllowedOrigins { get; set; } = new();

        // Allowed HTTP methods
        public List<string> AllowedMethods { get; set; } = new()
        {
            "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"
        };

        // Allowed request headers
        public List<string> AllowedHeaders { get; set; } = new()
        {
            "Content-Type", "Authorization", "X-API-Key", "X-Requested-With"
        };

        // Headers exposed to the browser
        public List<string> ExposedHeaders { get; set; } = new()
        {
            "X-Quota-Limit", "X-Quota-Used", "X-Quota-Remaining", "Retry-After"
        };

        // Allow credentials (cookies, auth headers)
        public bool AllowCredentials { get; set; } = true;

        // Preflight cache duration in seconds (default: 24 hours)
        public int MaxAgeSeconds { get; set; } = 86400;
    }

    public class CorsMiddleware : IFunctionsWorkerMiddleware
    {
        private readonly ILogger<CorsMiddleware> _logger;
        private readonly CorsOptions _options;

        public CorsMiddleware(
            ILogger<CorsMiddleware> logger,
            IOptions<CorsOptions> options)
        {
            _logger = logger;
            _options = options.Value;
        }

        public async Task Invoke(FunctionContext context, FunctionExecutionDelegate next)
        {
            var httpContext = context.GetHttpContext();
            if (httpContext is null)
            {
                await next(context);
                return;
            }

            var origin = httpContext.Request.Headers.Origin.FirstOrDefault();

            // Check if the request origin is allowed
            if (!string.IsNullOrEmpty(origin) && IsOriginAllowed(origin))
            {
                // Add CORS headers via OnStarting to ensure they're on ALL responses
                httpContext.Response.OnStarting(() =>
                {
                    httpContext.Response.Headers["Access-Control-Allow-Origin"] = origin;
                    httpContext.Response.Headers["Access-Control-Allow-Methods"] = string.Join(", ", _options.AllowedMethods);
                    httpContext.Response.Headers["Access-Control-Allow-Headers"] = string.Join(", ", _options.AllowedHeaders);

                    if (_options.ExposedHeaders.Count > 0)
                        httpContext.Response.Headers["Access-Control-Expose-Headers"] = string.Join(", ", _options.ExposedHeaders);

                    if (_options.AllowCredentials)
                        httpContext.Response.Headers["Access-Control-Allow-Credentials"] = "true";

                    httpContext.Response.Headers["Access-Control-Max-Age"] = _options.MaxAgeSeconds.ToString();

                    return Task.CompletedTask;
                });

                // Handle preflight OPTIONS request — respond immediately without hitting the function
                if (HttpMethods.IsOptions(httpContext.Request.Method))
                {
                    _logger.LogInformation("CORS preflight handled for origin: {Origin}", origin);
                    httpContext.Response.StatusCode = StatusCodes.Status204NoContent;
                    return; // Don't call next — preflight is handled
                }
            }
            else if (!string.IsNullOrEmpty(origin))
            {
                _logger.LogWarning("CORS: Blocked request from unauthorized origin: {Origin}", origin);
            }

            await next(context);
        }

        private bool IsOriginAllowed(string origin)
        {
            // Allow all if wildcard is configured
            if (_options.AllowedOrigins.Contains("*"))
                return true;

            return _options.AllowedOrigins.Any(allowed =>
                allowed.Equals(origin, StringComparison.OrdinalIgnoreCase));
        }
    }
}
