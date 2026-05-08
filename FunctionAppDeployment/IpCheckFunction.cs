using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace FunctionAppDeployment
{
    public class IpCheckFunction
    {
        private readonly ILogger<IpCheckFunction> _logger;

        public IpCheckFunction(ILogger<IpCheckFunction> logger)
        {
            _logger = logger;
        }

        [Function("IpCheck")]
        public IActionResult Run([HttpTrigger(AuthorizationLevel.Anonymous, "get")] HttpRequest req)
        {
            var xff = req.Headers["X-Forwarded-For"].FirstOrDefault();
            var xRealIp = req.Headers["X-Real-IP"].FirstOrDefault();
            var remoteIp = req.HttpContext.Connection.RemoteIpAddress?.ToString();
            var clientCert = req.Headers["X-Client-IP"].FirstOrDefault();

            return new OkObjectResult(new
            {
                XForwardedFor = xff,
                XRealIP = xRealIp,
                XClientIP = clientCert,
                RemoteIpAddress = remoteIp,
                AllHeaders = req.Headers
                    .Where(h => h.Key.StartsWith("X-", StringComparison.OrdinalIgnoreCase))
                    .ToDictionary(h => h.Key, h => h.Value.ToString())
            });
        }
    }
}
