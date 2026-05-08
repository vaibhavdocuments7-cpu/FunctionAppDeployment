using Microsoft.AspNetCore.Http;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Middleware;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FunctionAppDeployment.Middleware
{
    public class ApiKeyOptions
    {
        // Header name where API key is expected
        public string HeaderName { get; set; } = "X-API-Key";

        // Query parameter name as fallback (e.g., ?api_key=xxx)
        public string QueryParamName { get; set; } = "api_key";

        // Dictionary of valid API keys → client name (for logging/tracking)
        public Dictionary<string, string> ValidApiKeys { get; set; } = new();

        // Functions that skip API key validation
        public List<string> ExcludedFunctions { get; set; } = new();
    }

    public class ApiKeyMiddleware : IFunctionsWorkerMiddleware
    {
        private readonly ILogger<ApiKeyMiddleware> _logger;
        private readonly ApiKeyOptions _options;

        public ApiKeyMiddleware(
            ILogger<ApiKeyMiddleware> logger,
            IOptions<ApiKeyOptions> options)
        {
            _logger = logger;
            _options = options.Value;
        }

        public async Task Invoke(FunctionContext context, FunctionExecutionDelegate next)
        {
            var httpContext = context.GetHttpContext();
            if (httpContext is null)
            {
                // Non-HTTP trigger — skip
                await next(context);
                return;
            }

            // Skip excluded functions
            var functionName = context.FunctionDefinition.Name;
            if (_options.ExcludedFunctions.Contains(functionName, StringComparer.OrdinalIgnoreCase))
            {
                await next(context);
                return;
            }

            // Extract API key from header or query string
            var apiKey = ExtractApiKey(httpContext.Request);
            if (string.IsNullOrEmpty(apiKey))
            {
                _logger.LogWarning("Missing API key for {Function}", functionName);
                await WriteUnauthorizedResponse(httpContext,
                    $"API key is required. Pass it via '{_options.HeaderName}' header or '{_options.QueryParamName}' query parameter.");
                return;
            }

            // Validate API key
            if (!_options.ValidApiKeys.TryGetValue(apiKey, out var clientName))
            {
                _logger.LogWarning("Invalid API key '{MaskedKey}' for {Function}",
                    MaskApiKey(apiKey), functionName);
                await WriteUnauthorizedResponse(httpContext, "Invalid API key.");
                return;
            }

            // Valid key — store client info in context for downstream use
            context.Items["ApiKeyClient"] = clientName;
            httpContext.Items["ApiKeyClient"] = clientName;
            _logger.LogInformation("API key validated for client: {Client} on {Function}",
                clientName, functionName);

            await next(context);
        }

        private string? ExtractApiKey(HttpRequest request)
        {
            // Check header first
            if (request.Headers.TryGetValue(_options.HeaderName, out var headerValue)
                && !string.IsNullOrEmpty(headerValue.FirstOrDefault()))
            {
                return headerValue.FirstOrDefault();
            }

            // Fallback to query parameter
            if (request.Query.TryGetValue(_options.QueryParamName, out var queryValue)
                && !string.IsNullOrEmpty(queryValue.FirstOrDefault()))
            {
                return queryValue.FirstOrDefault();
            }

            return null;
        }

        private string MaskApiKey(string apiKey)
        {
            if (apiKey.Length <= 4) return "****";
            return apiKey[..4] + new string('*', apiKey.Length - 4);
        }

        private async Task WriteUnauthorizedResponse(HttpContext httpContext, string message)
        {
            httpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await httpContext.Response.WriteAsJsonAsync(new
            {
                error = "Unauthorized",
                message
            });
        }
    }
}
