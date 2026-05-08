using Microsoft.AspNetCore.Http;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Middleware;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Net;

namespace FunctionAppDeployment.Middleware
{
    public class IpFilterOptions
    {
        // Whitelist mode: only these IPs/CIDRs are allowed (if empty, all are allowed)
        public List<string> AllowedIPs { get; set; } = new();

        // Blacklist mode: these IPs/CIDRs are always blocked
        public List<string> BlockedIPs { get; set; } = new();

        // Functions that skip IP filtering (e.g., health check)
        public List<string> ExcludedFunctions { get; set; } = new();
    }

    public class IpFilteringMiddleware : IFunctionsWorkerMiddleware
    {
        private readonly ILogger<IpFilteringMiddleware> _logger;
        private readonly IpFilterOptions _options;
        private readonly List<(IPAddress Network, int PrefixLength)> _allowedRanges;
        private readonly List<(IPAddress Network, int PrefixLength)> _blockedRanges;

        public IpFilteringMiddleware(
            ILogger<IpFilteringMiddleware> logger,
            IOptions<IpFilterOptions> options)
        {
            _logger = logger;
            _options = options.Value;
            _allowedRanges = ParseCidrList(_options.AllowedIPs);
            _blockedRanges = ParseCidrList(_options.BlockedIPs);
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

            var clientIp = GetClientIpAddress(httpContext);

            // Debug logging — see all IP sources
            var xff = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            var xRealIp = httpContext.Request.Headers["X-Real-IP"].FirstOrDefault();
            var remoteIp = httpContext.Connection.RemoteIpAddress;
            _logger.LogWarning("IP Debug — X-Forwarded-For: {XFF}, X-Real-IP: {XReal}, RemoteIP: {Remote}, Resolved: {Resolved}",
                xff, xRealIp, remoteIp, clientIp);

            if (clientIp is null)
            {
                _logger.LogWarning("Could not determine client IP for {Function}", functionName);
                await WriteForbiddenResponse(httpContext, "Unable to determine client IP address.");
                return;
            }

            // Check blocked list first (blacklist takes priority)
            if (_blockedRanges.Count > 0 && IsIpInRanges(clientIp, _blockedRanges))
            {
                _logger.LogWarning("Blocked IP {IP} attempted to access {Function}", clientIp, functionName);
                await WriteForbiddenResponse(httpContext, $"Access denied for IP: {clientIp}");
                return;
            }

            // Check allowed list (whitelist — if configured, only these IPs are allowed)
            if (_allowedRanges.Count > 0 && !IsIpInRanges(clientIp, _allowedRanges))
            {
                _logger.LogWarning("Unauthorized IP {IP} attempted to access {Function}", clientIp, functionName);
                await WriteForbiddenResponse(httpContext, $"Access denied for IP: {clientIp}");
                return;
            }

            _logger.LogInformation("IP {IP} allowed for {Function}", clientIp, functionName);
            await next(context);
        }

        private IPAddress? GetClientIpAddress(HttpContext httpContext)
        {
            // Azure App Service headers (priority order)
            string[] ipHeaders = [
                "X-Forwarded-For",
                "X-Client-IP",
                "X-Real-IP",
                "CLIENT-IP",
                "X-Original-For"
            ];

            foreach (var header in ipHeaders)
            {
                var value = httpContext.Request.Headers[header].FirstOrDefault();
                if (!string.IsNullOrEmpty(value))
                {
                    var ip = value.Split(',')[0].Trim();
                    // Remove port if present (e.g., "127.0.0.1:50662")
                    if (ip.Contains(':') && !ip.Contains('['))
                        ip = ip.Split(':')[0];

                    if (IPAddress.TryParse(ip, out var parsedIp))
                        return parsedIp;
                }
            }

            // Fall back to connection remote IP
            return httpContext.Connection.RemoteIpAddress;
        }

        private bool IsIpInRanges(IPAddress clientIp, List<(IPAddress Network, int PrefixLength)> ranges)
        {
            foreach (var (network, prefixLength) in ranges)
            {
                if (IsIpInRange(clientIp, network, prefixLength))
                    return true;
            }
            return false;
        }

        private bool IsIpInRange(IPAddress clientIp, IPAddress network, int prefixLength)
        {
            // Exact match (single IP, prefix = 32 or 128)
            if (clientIp.Equals(network))
                return true;

            var clientBytes = clientIp.GetAddressBytes();
            var networkBytes = network.GetAddressBytes();

            if (clientBytes.Length != networkBytes.Length)
                return false;

            var bits = prefixLength;
            for (int i = 0; i < networkBytes.Length && bits > 0; i++)
            {
                var mask = (byte)(bits >= 8 ? 0xFF : (0xFF << (8 - bits)));
                if ((clientBytes[i] & mask) != (networkBytes[i] & mask))
                    return false;
                bits -= 8;
            }
            return true;
        }

        private List<(IPAddress Network, int PrefixLength)> ParseCidrList(List<string> entries)
        {
            var result = new List<(IPAddress, int)>();
            foreach (var entry in entries)
            {
                var parts = entry.Trim().Split('/');
                if (IPAddress.TryParse(parts[0], out var ip))
                {
                    var prefix = parts.Length > 1 && int.TryParse(parts[1], out var p)
                        ? p
                        : (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128);
                    result.Add((ip, prefix));
                }
                else
                {
                    // Log invalid entry but don't crash
                }
            }
            return result;
        }

        private async Task WriteForbiddenResponse(HttpContext httpContext, string message)
        {
            httpContext.Response.StatusCode = StatusCodes.Status403Forbidden;
            await httpContext.Response.WriteAsJsonAsync(new
            {
                error = "Forbidden",
                message
            });
        }
    }
}
