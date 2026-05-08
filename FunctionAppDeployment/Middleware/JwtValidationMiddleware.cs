using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Middleware;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace FunctionAppDeployment.Middleware
{
    public class JwtValidationOptions
    {
        public string TenantId { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string Instance { get; set; } = "https://login.microsoftonline.com/";
        public List<string> AllowedAudiences { get; set; } = new();

        // Functions that skip JWT validation (e.g., health check)
        public List<string> ExcludedFunctions { get; set; } = new();
    }

    public class JwtValidationMiddleware : IFunctionsWorkerMiddleware
    {
        private readonly ILogger<JwtValidationMiddleware> _logger;
        private readonly JwtValidationOptions _options;
        private readonly ConfigurationManager<OpenIdConnectConfiguration> _configManager;

        public JwtValidationMiddleware(
            ILogger<JwtValidationMiddleware> logger,
            IOptions<JwtValidationOptions> options)
        {
            _logger = logger;
            _options = options.Value;

            var authority = $"{_options.Instance}{_options.TenantId}/v2.0";
            var metadataUrl = $"{authority}/.well-known/openid-configuration";

            _configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                metadataUrl,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever());
        }

        public async Task Invoke(FunctionContext context, FunctionExecutionDelegate next)
        {
            // Use HttpContext (ASP.NET Core integration) instead of HttpRequestData
            var httpContext = context.GetHttpContext();
            if (httpContext is null)
            {
                // Non-HTTP trigger — skip
                await next(context);
                return;
            }

            // Skip excluded functions (e.g., health endpoints)
            var functionName = context.FunctionDefinition.Name;
            if (_options.ExcludedFunctions.Contains(functionName, StringComparer.OrdinalIgnoreCase))
            {
                await next(context);
                return;
            }

            // Extract token from Authorization header
            var token = ExtractToken(httpContext.Request);
            if (string.IsNullOrEmpty(token))
            {
                _logger.LogWarning("Missing or invalid Authorization header for {Function}", functionName);
                await WriteUnauthorizedResponse(httpContext, "Missing or invalid Authorization header. Expected: Bearer <token>");
                return;
            }

            // Validate the JWT token
            var validationResult = await ValidateTokenAsync(token);
            if (!validationResult.IsValid)
            {
                _logger.LogWarning("Token validation failed for {Function}: {Error}",
                    functionName, validationResult.ErrorMessage);
                await WriteUnauthorizedResponse(httpContext, $"Token validation failed: {validationResult.ErrorMessage}");
                return;
            }

            // Token is valid — store claims in FunctionContext for downstream use
            context.Items["User"] = validationResult.ClaimsPrincipal;
            httpContext.User = validationResult.ClaimsPrincipal!;
            _logger.LogInformation("JWT validated for user: {User}",
                validationResult.ClaimsPrincipal?.Identity?.Name ?? "unknown");

            await next(context);
        }

        private string? ExtractToken(HttpRequest request)
        {
            var authHeader = request.Headers.Authorization.FirstOrDefault();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                return null;

            return authHeader["Bearer ".Length..].Trim();
        }

        private async Task<JwtTokenValidationResult> ValidateTokenAsync(string token)
        {
            try
            {
                var config = await _configManager.GetConfigurationAsync(CancellationToken.None);

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuers = new[]
                    {
                        $"https://login.microsoftonline.com/{_options.TenantId}/v2.0",
                        $"https://sts.windows.net/{_options.TenantId}/"
                    },
                    ValidateAudience = true,
                    ValidAudiences = _options.AllowedAudiences.Count > 0
                        ? _options.AllowedAudiences
                        : new List<string> { _options.ClientId },
                    ValidateLifetime = true,
                    IssuerSigningKeys = config.SigningKeys,
                    ClockSkew = TimeSpan.FromMinutes(2)
                };

                var handler = new JwtSecurityTokenHandler();
                var principal = handler.ValidateToken(token, validationParameters, out _);

                return new JwtTokenValidationResult { IsValid = true, ClaimsPrincipal = principal };
            }
            catch (SecurityTokenExpiredException)
            {
                return new JwtTokenValidationResult { IsValid = false, ErrorMessage = "Token has expired" };
            }
            catch (SecurityTokenInvalidAudienceException)
            {
                return new JwtTokenValidationResult { IsValid = false, ErrorMessage = "Invalid audience" };
            }
            catch (SecurityTokenInvalidIssuerException)
            {
                return new JwtTokenValidationResult { IsValid = false, ErrorMessage = "Invalid issuer" };
            }
            catch (Exception ex)
            {
                return new JwtTokenValidationResult { IsValid = false, ErrorMessage = ex.Message };
            }
        }

        private async Task WriteUnauthorizedResponse(HttpContext httpContext, string message)
        {
            httpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
            httpContext.Response.Headers.WWWAuthenticate = "Bearer";
            await httpContext.Response.WriteAsJsonAsync(new
            {
                error = "Unauthorized",
                message
            });
        }
    }

    public class JwtTokenValidationResult
    {
        public bool IsValid { get; set; }
        public string? ErrorMessage { get; set; }
        public System.Security.Claims.ClaimsPrincipal? ClaimsPrincipal { get; set; }
    }
}
