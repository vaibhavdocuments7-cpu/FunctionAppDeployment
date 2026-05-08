using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Middleware;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FunctionAppDeployment.Middleware
{
    public class RequestValidationOptions
    {
        // Max allowed request body size in bytes (default: 1MB)
        public long MaxBodySizeBytes { get; set; } = 1_048_576;

        // Max URL length (default: 2048 characters)
        public int MaxUrlLength { get; set; } = 2048;

        // Max query string length (default: 1024 characters)
        public int MaxQueryStringLength { get; set; } = 1024;

        // Max header value length (default: 8192 characters)
        public int MaxHeaderValueLength { get; set; } = 8192;

        // Enable/disable specific checks
        public bool BlockSqlInjection { get; set; } = true;
        public bool BlockXss { get; set; } = true;
        public bool BlockPathTraversal { get; set; } = true;
        public bool BlockCommandInjection { get; set; } = true;
        public bool EnforceContentType { get; set; } = true;

        // Allowed content types for POST/PUT requests
        public List<string> AllowedContentTypes { get; set; } = new()
        {
            "application/json",
            "application/xml",
            "text/plain",
            "multipart/form-data",
            "application/x-www-form-urlencoded"
        };

        // Functions that skip validation
        public List<string> ExcludedFunctions { get; set; } = new();
    }

    public class RequestValidationMiddleware : IFunctionsWorkerMiddleware
    {
        private readonly ILogger<RequestValidationMiddleware> _logger;
        private readonly RequestValidationOptions _options;

        // SQL Injection patterns
        private static readonly Regex SqlInjectionPattern = new(
            @"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC|EXECUTE)\b.*\b(FROM|INTO|TABLE|DATABASE|SET|WHERE)\b)" +
            @"|('(\s*)(OR|AND)(\s*)('|[0-9]|[a-zA-Z]))" +
            @"|(--\s)" +
            @"|(;\s*(DROP|DELETE|UPDATE|INSERT))" +
            @"|(\b(OR|AND)\b\s+\d+\s*=\s*\d+)" +
            @"|(WAITFOR\s+DELAY)" +
            @"|(BENCHMARK\s*\()",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // XSS patterns
        private static readonly Regex XssPattern = new(
            @"(<script[^>]*>)" +
            @"|(<\/script>)" +
            @"|(javascript\s*:)" +
            @"|(on(load|error|click|mouseover|submit|focus|blur)\s*=)" +
            @"|(<iframe[^>]*>)" +
            @"|(<object[^>]*>)" +
            @"|(<embed[^>]*>)" +
            @"|(<img[^>]*\s+on\w+\s*=)" +
            @"|(document\.(cookie|write|location))" +
            @"|(window\.(location|open))" +
            @"|(eval\s*\()" +
            @"|(alert\s*\()",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // Path Traversal patterns
        private static readonly Regex PathTraversalPattern = new(
            @"(\.\.[\\/])" +
            @"|(\.\.%2[fF])" +
            @"|(%2[eE]%2[eE][\\/])" +
            @"|(%252e%252e)" +
            @"|(/etc/(passwd|shadow|hosts))" +
            @"|(\\windows\\system32)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // Command Injection patterns
        private static readonly Regex CommandInjectionPattern = new(
            @"(;\s*(ls|cat|rm|wget|curl|bash|sh|cmd|powershell))" +
            @"|(\|\s*(ls|cat|rm|wget|curl|bash|sh))" +
            @"|(`[^`]*`)" +
            @"|(\$\([^)]*\))" +
            @"|(\b(rm\s+-rf|chmod\s+777|wget\s+http|curl\s+http)\b)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public RequestValidationMiddleware(
            ILogger<RequestValidationMiddleware> logger,
            IOptions<RequestValidationOptions> options)
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

            var functionName = context.FunctionDefinition.Name;
            if (_options.ExcludedFunctions.Contains(functionName, StringComparer.OrdinalIgnoreCase))
            {
                await next(context);
                return;
            }

            // 1. Check URL length
            var url = httpContext.Request.Path + httpContext.Request.QueryString;
            if (url.Length > _options.MaxUrlLength)
            {
                await WriteBlockedResponse(httpContext, "URL exceeds maximum allowed length.", "URL_TOO_LONG");
                return;
            }

            // 2. Check query string length
            if (httpContext.Request.QueryString.HasValue &&
                httpContext.Request.QueryString.Value!.Length > _options.MaxQueryStringLength)
            {
                await WriteBlockedResponse(httpContext, "Query string exceeds maximum allowed length.", "QUERY_TOO_LONG");
                return;
            }

            // 3. Check content length for POST/PUT
            if (HttpMethods.IsPost(httpContext.Request.Method) || HttpMethods.IsPut(httpContext.Request.Method))
            {
                if (httpContext.Request.ContentLength > _options.MaxBodySizeBytes)
                {
                    await WriteBlockedResponse(httpContext, 
                        $"Request body exceeds maximum allowed size of {_options.MaxBodySizeBytes / 1024}KB.", 
                        "BODY_TOO_LARGE");
                    return;
                }

                // 4. Validate content type
                if (_options.EnforceContentType && httpContext.Request.ContentType != null)
                {
                    var contentType = httpContext.Request.ContentType.Split(';')[0].Trim().ToLower();
                    if (!_options.AllowedContentTypes.Any(ct => ct.Equals(contentType, StringComparison.OrdinalIgnoreCase)))
                    {
                        await WriteBlockedResponse(httpContext,
                            $"Content-Type '{contentType}' is not allowed.", "INVALID_CONTENT_TYPE");
                        return;
                    }
                }
            }

            // 5. Check header values length
            foreach (var header in httpContext.Request.Headers)
            {
                if (header.Value.ToString().Length > _options.MaxHeaderValueLength)
                {
                    await WriteBlockedResponse(httpContext,
                        $"Header '{header.Key}' exceeds maximum allowed length.", "HEADER_TOO_LONG");
                    return;
                }
            }

            // 6. Scan URL, query string, and headers for attack patterns
            var urlToScan = Uri.UnescapeDataString(url);
            var queryString = httpContext.Request.QueryString.HasValue
                ? Uri.UnescapeDataString(httpContext.Request.QueryString.Value!)
                : string.Empty;

            // Combine all scannable inputs
            var scanTargets = new List<(string Source, string Value)>
            {
                ("URL", urlToScan),
                ("QueryString", queryString)
            };

            // Scan selected headers (skip standard headers)
            string[] headersToScan = ["Referer", "User-Agent", "X-Custom-Header"];
            foreach (var headerName in headersToScan)
            {
                if (httpContext.Request.Headers.TryGetValue(headerName, out var headerValue))
                    scanTargets.Add(($"Header:{headerName}", headerValue.ToString()));
            }

            // Scan query parameters individually
            foreach (var param in httpContext.Request.Query)
            {
                scanTargets.Add(($"QueryParam:{param.Key}", param.Value.ToString()));
            }

            foreach (var (source, value) in scanTargets)
            {
                if (string.IsNullOrEmpty(value)) continue;

                // SQL Injection check
                if (_options.BlockSqlInjection && SqlInjectionPattern.IsMatch(value))
                {
                    _logger.LogWarning("SQL Injection attempt detected in {Source}: {Value}",
                        source, TruncateForLog(value));
                    await WriteBlockedResponse(httpContext,
                        "Request blocked: Potential SQL injection detected.", "SQL_INJECTION");
                    return;
                }

                // XSS check
                if (_options.BlockXss && XssPattern.IsMatch(value))
                {
                    _logger.LogWarning("XSS attempt detected in {Source}: {Value}",
                        source, TruncateForLog(value));
                    await WriteBlockedResponse(httpContext,
                        "Request blocked: Potential cross-site scripting (XSS) detected.", "XSS");
                    return;
                }

                // Path Traversal check
                if (_options.BlockPathTraversal && PathTraversalPattern.IsMatch(value))
                {
                    _logger.LogWarning("Path traversal attempt detected in {Source}: {Value}",
                        source, TruncateForLog(value));
                    await WriteBlockedResponse(httpContext,
                        "Request blocked: Potential path traversal detected.", "PATH_TRAVERSAL");
                    return;
                }

                // Command Injection check
                if (_options.BlockCommandInjection && CommandInjectionPattern.IsMatch(value))
                {
                    _logger.LogWarning("Command injection attempt detected in {Source}: {Value}",
                        source, TruncateForLog(value));
                    await WriteBlockedResponse(httpContext,
                        "Request blocked: Potential command injection detected.", "COMMAND_INJECTION");
                    return;
                }
            }

            // 7. Scan request body for POST/PUT (read and re-buffer)
            if (HttpMethods.IsPost(httpContext.Request.Method) || HttpMethods.IsPut(httpContext.Request.Method))
            {
                httpContext.Request.EnableBuffering();
                using var reader = new StreamReader(httpContext.Request.Body, leaveOpen: true);
                var body = await reader.ReadToEndAsync();
                httpContext.Request.Body.Position = 0; // Reset for downstream

                if (!string.IsNullOrEmpty(body))
                {
                    if (_options.BlockSqlInjection && SqlInjectionPattern.IsMatch(body))
                    {
                        _logger.LogWarning("SQL Injection in request body for {Function}", functionName);
                        await WriteBlockedResponse(httpContext,
                            "Request blocked: Potential SQL injection in request body.", "SQL_INJECTION_BODY");
                        return;
                    }

                    if (_options.BlockXss && XssPattern.IsMatch(body))
                    {
                        _logger.LogWarning("XSS in request body for {Function}", functionName);
                        await WriteBlockedResponse(httpContext,
                            "Request blocked: Potential XSS in request body.", "XSS_BODY");
                        return;
                    }
                }
            }

            _logger.LogInformation("Request validation passed for {Function}", functionName);
            await next(context);
        }

        private string TruncateForLog(string value)
        {
            return value.Length > 100 ? value[..100] + "..." : value;
        }

        private async Task WriteBlockedResponse(HttpContext httpContext, string message, string code)
        {
            httpContext.Response.StatusCode = StatusCodes.Status400BadRequest;
            await httpContext.Response.WriteAsJsonAsync(new
            {
                error = "Bad Request",
                code,
                message
            });
        }
    }
}
