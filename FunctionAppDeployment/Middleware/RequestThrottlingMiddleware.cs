using System.Collections.Concurrent;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Middleware;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FunctionAppDeployment.Middleware
{
    public class ThrottleOptions
    {
        // Default daily quota (applies to all clients unless overridden)
        public int DefaultDailyQuota { get; set; } = 10000;

        // Per-client daily quota overrides (key = client name from API Key middleware)
        public Dictionary<string, int> ClientQuotas { get; set; } = new();

        // Functions that skip throttling
        public List<string> ExcludedFunctions { get; set; } = new();
    }

    public class RequestThrottlingMiddleware : IFunctionsWorkerMiddleware
    {
        private readonly ILogger<RequestThrottlingMiddleware> _logger;
        private readonly ThrottleOptions _options;

        // Track usage per client per day: "clientKey:yyyy-MM-dd" → count
        private readonly ConcurrentDictionary<string, ClientUsage> _usageTracker = new();

        public RequestThrottlingMiddleware(
            ILogger<RequestThrottlingMiddleware> logger,
            IOptions<ThrottleOptions> options)
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

            // Skip excluded functions
            var functionName = context.FunctionDefinition.Name;
            if (_options.ExcludedFunctions.Contains(functionName, StringComparer.OrdinalIgnoreCase))
            {
                await next(context);
                return;
            }

            // Identify client (from API Key middleware or IP)
            var clientKey = GetClientKey(context, httpContext);
            var today = DateTime.UtcNow.ToString("yyyy-MM-dd");
            var trackingKey = $"{clientKey}:{today}";

            // Get or create usage record
            var usage = _usageTracker.GetOrAdd(trackingKey, _ => new ClientUsage
            {
                Date = today,
                Count = 0
            });

            // Clean up old entries (previous days)
            CleanupOldEntries(today);

            // Get quota for this client
            var quota = GetQuotaForClient(clientKey);

            // Check if quota exceeded
            var currentCount = Interlocked.Increment(ref usage.Count);
            if (currentCount > quota)
            {
                _logger.LogWarning("Throttle: Client {Client} exceeded daily quota ({Count}/{Quota})",
                    clientKey, currentCount, quota);

                var resetTime = DateTime.UtcNow.Date.AddDays(1);
                var secondsUntilReset = (int)(resetTime - DateTime.UtcNow).TotalSeconds;

                httpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                httpContext.Response.Headers.RetryAfter = secondsUntilReset.ToString();
                httpContext.Response.Headers["X-Quota-Limit"] = quota.ToString();
                httpContext.Response.Headers["X-Quota-Used"] = currentCount.ToString();
                httpContext.Response.Headers["X-Quota-Reset"] = resetTime.ToString("o");

                await httpContext.Response.WriteAsJsonAsync(new
                {
                    error = "Quota Exceeded",
                    message = $"Daily quota of {quota} requests exceeded. Resets at {resetTime:yyyy-MM-dd HH:mm:ss} UTC.",
                    quotaLimit = quota,
                    quotaUsed = currentCount,
                    quotaResetsAt = resetTime.ToString("o"),
                    retryAfterSeconds = secondsUntilReset
                });
                return;
            }

            // Add quota headers to successful responses
            httpContext.Response.OnStarting(() =>
            {
                httpContext.Response.Headers["X-Quota-Limit"] = quota.ToString();
                httpContext.Response.Headers["X-Quota-Used"] = currentCount.ToString();
                httpContext.Response.Headers["X-Quota-Remaining"] = (quota - currentCount).ToString();
                return Task.CompletedTask;
            });

            _logger.LogInformation("Throttle: Client {Client} usage {Count}/{Quota}",
                clientKey, currentCount, quota);

            await next(context);
        }

        private string GetClientKey(FunctionContext context, HttpContext httpContext)
        {
            // Use client name from API Key middleware if available
            if (context.Items.TryGetValue("ApiKeyClient", out var clientObj) && clientObj is string clientName)
                return clientName;

            // Fall back to IP-based tracking
            var ip = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            return $"ip:{ip}";
        }

        private int GetQuotaForClient(string clientKey)
        {
            if (_options.ClientQuotas.TryGetValue(clientKey, out var quota))
                return quota;

            return _options.DefaultDailyQuota;
        }

        private void CleanupOldEntries(string today)
        {
            var keysToRemove = _usageTracker.Keys
                .Where(k => !k.EndsWith(today))
                .ToList();

            foreach (var key in keysToRemove)
                _usageTracker.TryRemove(key, out _);
        }
    }

    public class ClientUsage
    {
        public string Date { get; set; } = string.Empty;
        public int Count;
    }
}
