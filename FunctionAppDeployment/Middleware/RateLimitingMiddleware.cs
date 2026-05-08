using System.Collections.Concurrent;
using System.Threading.RateLimiting;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Middleware;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FunctionAppDeployment.Middleware
{
    public class RateLimitOptions
    {
        public int PermitLimit { get; set; } = 10;
        public int WindowInSeconds { get; set; } = 60;
        public int QueueLimit { get; set; } = 0;
    }

    public class RateLimitingMiddleware : IFunctionsWorkerMiddleware
    {
        private readonly ILogger<RateLimitingMiddleware> _logger;
        private readonly RateLimitOptions _options;
        private readonly ConcurrentDictionary<string, RateLimiter> _limiters = new();

        public RateLimitingMiddleware(
            ILogger<RateLimitingMiddleware> logger,
            IOptions<RateLimitOptions> options)
        {
            _logger = logger;
            _options = options.Value;
        }

        public async Task Invoke(FunctionContext context, FunctionExecutionDelegate next)
        {
            var httpReqData = await context.GetHttpRequestDataAsync();
            if (httpReqData is null)
            {
                // Non-HTTP trigger (Queue, Blob, etc.) — skip rate limiting
                await next(context);
                return;
            }

            var clientKey = GetClientKey(httpReqData);
            var limiter = _limiters.GetOrAdd(clientKey, _ => CreateLimiter());

            using var lease = await limiter.AcquireAsync(1, context.CancellationToken);

            if (lease.IsAcquired)
            {
                _logger.LogInformation("Rate limit: Request permitted for {ClientKey}", clientKey);
                await next(context);
            }
            else
            {
                _logger.LogWarning("Rate limit exceeded for {ClientKey}", clientKey);

                var httpContext = context.GetHttpContext();
                if (httpContext is not null)
                {
                    httpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                    httpContext.Response.Headers.RetryAfter = _options.WindowInSeconds.ToString();
                    await httpContext.Response.WriteAsJsonAsync(new
                    {
                        error = "Rate limit exceeded",
                        retryAfterSeconds = _options.WindowInSeconds,
                        message = $"You have exceeded the limit of {_options.PermitLimit} requests per {_options.WindowInSeconds} seconds."
                    });
                }
            }
        }

        private string GetClientKey(HttpRequestData requestData)
        {
            // Priority: API Key header → X-Forwarded-For → Connection IP
            if (requestData.Headers.TryGetValues("X-API-Key", out var apiKeyValues))
                return $"apikey:{apiKeyValues.First()}";

            if (requestData.Headers.TryGetValues("X-Forwarded-For", out var forwardedValues))
                return $"ip:{forwardedValues.First().Split(',')[0].Trim()}";

            return $"ip:{requestData.Url.Host}";
        }

        private RateLimiter CreateLimiter()
        {
            return new FixedWindowRateLimiter(new FixedWindowRateLimiterOptions
            {
                PermitLimit = _options.PermitLimit,
                Window = TimeSpan.FromSeconds(_options.WindowInSeconds),
                QueueLimit = _options.QueueLimit,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                AutoReplenishment = true
            });
        }
    }
}
