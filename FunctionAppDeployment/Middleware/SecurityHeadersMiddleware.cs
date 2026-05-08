using Microsoft.AspNetCore.Http;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Middleware;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FunctionAppDeployment.Middleware
{
    public class SecurityHeadersOptions
    {
        // HSTS (HTTP Strict Transport Security)
        // Forces browsers to use HTTPS only. Prevents downgrade attacks.
        public bool EnableHsts { get; set; } = true;
        public int HstsMaxAgeSeconds { get; set; } = 31536000; // 1 year
        public bool HstsIncludeSubDomains { get; set; } = true;

        // Content Security Policy (CSP)
        // Controls which resources (scripts, styles, images) the browser can load.
        // Prevents XSS by restricting script sources.
        public bool EnableCsp { get; set; } = true;
        public string CspPolicy { get; set; } = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'";

        // X-Content-Type-Options
        // Prevents browser from MIME-sniffing (guessing content type).
        // Stops attacks where a file is served as wrong type (e.g., JS disguised as image).
        public bool EnableNoSniff { get; set; } = true;

        // X-Frame-Options
        // Prevents your page from being embedded in <iframe>.
        // Stops clickjacking attacks where attacker overlays invisible iframe.
        public bool EnableFrameOptions { get; set; } = true;
        public string FrameOptionsValue { get; set; } = "DENY"; // DENY | SAMEORIGIN

        // X-XSS-Protection
        // Legacy browser XSS filter (for older browsers that don't support CSP).
        public bool EnableXssProtection { get; set; } = true;

        // Referrer-Policy
        // Controls how much referrer info is sent when navigating away.
        // "strict-origin-when-cross-origin" = send origin only for cross-origin requests.
        public bool EnableReferrerPolicy { get; set; } = true;
        public string ReferrerPolicy { get; set; } = "strict-origin-when-cross-origin";

        // Permissions-Policy (formerly Feature-Policy)
        // Controls which browser features (camera, mic, geolocation) your app can use.
        public bool EnablePermissionsPolicy { get; set; } = true;
        public string PermissionsPolicy { get; set; } = "camera=(), microphone=(), geolocation=(), payment=()";

        // Cache-Control
        // Prevents sensitive API responses from being cached by browsers or proxies.
        public bool EnableNoCacheForApi { get; set; } = true;
    }

    public class SecurityHeadersMiddleware : IFunctionsWorkerMiddleware
    {
        private readonly ILogger<SecurityHeadersMiddleware> _logger;
        private readonly SecurityHeadersOptions _options;

        public SecurityHeadersMiddleware(
            ILogger<SecurityHeadersMiddleware> logger,
            IOptions<SecurityHeadersOptions> options)
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

            // Register a callback to add headers BEFORE the response is sent.
            // Using OnStarting ensures headers are added even if downstream middleware
            // writes to the response directly.
            httpContext.Response.OnStarting(() =>
            {
                AddSecurityHeaders(httpContext.Response);
                return Task.CompletedTask;
            });

            await next(context);
        }

        private void AddSecurityHeaders(HttpResponse response)
        {
            // 1. HSTS — Force HTTPS
            // Browser remembers: "Always use HTTPS for this domain for the next 1 year"
            // Prevents: SSL stripping / downgrade attacks
            if (_options.EnableHsts)
            {
                var hstsValue = $"max-age={_options.HstsMaxAgeSeconds}";
                if (_options.HstsIncludeSubDomains)
                    hstsValue += "; includeSubDomains";

                response.Headers["Strict-Transport-Security"] = hstsValue;
            }

            // 2. CSP — Content Security Policy
            // Tells browser: "Only load scripts/styles/images from these sources"
            // Prevents: XSS attacks, data injection, clickjacking
            // Example: default-src 'self' = only load resources from same origin
            if (_options.EnableCsp)
            {
                response.Headers["Content-Security-Policy"] = _options.CspPolicy;
            }

            // 3. X-Content-Type-Options: nosniff
            // Tells browser: "Don't guess the content type, trust the Content-Type header"
            // Prevents: MIME confusion attacks (e.g., uploading .js disguised as .png)
            if (_options.EnableNoSniff)
            {
                response.Headers["X-Content-Type-Options"] = "nosniff";
            }

            // 4. X-Frame-Options
            // Tells browser: "Don't allow this page to be loaded in an iframe"
            // Prevents: Clickjacking (attacker puts invisible iframe over a button)
            // DENY = no iframes at all, SAMEORIGIN = only same domain can iframe
            if (_options.EnableFrameOptions)
            {
                response.Headers["X-Frame-Options"] = _options.FrameOptionsValue;
            }

            // 5. X-XSS-Protection
            // Legacy XSS filter for older browsers (IE, older Chrome)
            // Modern browsers use CSP instead, but this is defense-in-depth
            // "1; mode=block" = if XSS detected, block the page entirely
            if (_options.EnableXssProtection)
            {
                response.Headers["X-XSS-Protection"] = "1; mode=block";
            }

            // 6. Referrer-Policy
            // Controls what URL info is sent in the Referer header when clicking links
            // "strict-origin-when-cross-origin":
            //   - Same origin: send full URL
            //   - Cross origin (HTTPS→HTTPS): send origin only (no path/query)
            //   - HTTPS→HTTP: send nothing
            if (_options.EnableReferrerPolicy)
            {
                response.Headers["Referrer-Policy"] = _options.ReferrerPolicy;
            }

            // 7. Permissions-Policy
            // Tells browser: "This app doesn't use camera, microphone, etc."
            // Prevents: Malicious scripts from accessing device features
            // camera=() means no one can access camera, not even same origin
            if (_options.EnablePermissionsPolicy)
            {
                response.Headers["Permissions-Policy"] = _options.PermissionsPolicy;
            }

            // 8. Cache-Control for API responses
            // Prevents: Sensitive data being stored in browser/proxy cache
            // no-store = don't cache at all, no-cache = revalidate every time
            if (_options.EnableNoCacheForApi)
            {
                response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate";
                response.Headers["Pragma"] = "no-cache"; // HTTP/1.0 backward compatibility
            }
        }
    }
}
