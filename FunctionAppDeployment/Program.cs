using FunctionAppDeployment.Middleware;
using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = FunctionsApplication.CreateBuilder(args);

builder.ConfigureFunctionsWebApplication();

// ============================================================================
// 1. RATE LIMITING CONFIGURATION
// ============================================================================
// Uses .NET 8 built-in System.Threading.RateLimiting (FixedWindowRateLimiter)
// ⚠️ LIMITATION: This is in-memory, per-instance rate limiting.
//    If your Function App scales to multiple instances, each instance has its own counter.
//    For distributed rate limiting across instances, use:
//    - Azure API Management (APIM) rate-limit policy
//    - Azure Redis Cache with a distributed rate limiter
//
// HOW IT WORKS:
//    - Tracks requests per client (identified by X-API-Key header → X-Forwarded-For → Host IP)
//    - Returns HTTP 429 (Too Many Requests) with Retry-After header when limit exceeded
//    - Only applies to HTTP triggers; Queue/Blob triggers are skipped automatically
builder.Services.Configure<RateLimitOptions>(options =>
{
    options.PermitLimit = 3;       // Max 3 requests per window (set low for testing, use 100+ in production)
    options.WindowInSeconds = 10;   // Per 10-second window (use 60+ in production)
    options.QueueLimit = 0;         // No queuing — reject immediately when limit reached
});

// ============================================================================
// 2. JWT VALIDATION CONFIGURATION (Azure AD / Entra ID)
// ============================================================================
// Validates Bearer tokens issued by Azure AD using OpenID Connect discovery.
// Auto-fetches signing keys from: https://login.microsoftonline.com/{TenantId}/v2.0/.well-known/openid-configuration
//
// SETUP STEPS (Azure Portal → Entra ID → App Registrations):
//   1. Register your app → get TenantId and ClientId
//   2. Expose an API → Set Application ID URI (api://{ClientId})
//   3. Add a scope (e.g., "access_as_user") under Expose an API
//   4. Add Redirect URI under Authentication (e.g., https://app.insomnia.rest/oauth/redirect)
//   5. Create a Client Secret under Certificates & Secrets
//
// ISSUES FACED & FIXES:
//   ❌ AADSTS500011: "Resource principal named api://{ClientId} was not found"
//      → FIX: Go to Expose an API → Set the Application ID URI (it was missing)
//
//   ❌ AADSTS65005: "Application asked for scope 'access_as_user' that doesn't exist"
//      → FIX: Go to Expose an API → Click "+ Add a scope" → Create "access_as_user" scope
//
//   ❌ AADSTS500113: "No reply address is registered for the application"
//      → FIX: Go to Authentication → Add Redirect URI: https://app.insomnia.rest/oauth/redirect
//
//   ❌ AADSTS50011: "Redirect URI mismatch"
//      → FIX: The Redirect URI in Insomnia must EXACTLY match the one registered in Azure AD
//             Insomnia uses: https://app.insomnia.rest/oauth/redirect (not localhost)
//
//   ❌ "Token validation failed: Invalid audience"
//      → FIX: Token's audience (aud) was "api://ClientId" but AllowedAudiences only had "ClientId"
//             Solution: Add BOTH formats to AllowedAudiences:
//             - "api://ClientId" (v2.0 tokens with custom scope)
//             - "ClientId" (v1.0 tokens / Graph tokens)
//
// TESTING WITH INSOMNIA:
//   Auth tab → OAuth 2.0 → Authorization Code grant
//   - Auth URL:    https://login.microsoftonline.com/{TenantId}/oauth2/v2.0/authorize
//   - Token URL:   https://login.microsoftonline.com/{TenantId}/oauth2/v2.0/token
//   - Client ID:   {your-client-id}
//   - Client Secret: {your-client-secret}
//   - Scope:       api://{ClientId}/access_as_user
//   - Redirect URL: https://app.insomnia.rest/oauth/redirect
builder.Services.Configure<JwtValidationOptions>(options =>
{
    options.TenantId = Environment.GetEnvironmentVariable("AzureAd__TenantId") ?? "79e7043b-2d89-4454-9f07-1d8ceb3f0399";
    options.ClientId = Environment.GetEnvironmentVariable("AzureAd__ClientId") ?? "1d96da07-b36b-4790-a3a8-4d2d996d1a3d";
    options.Instance = "https://login.microsoftonline.com/";
    // ✅ FIX: Accept both audience formats (v2.0 with api:// prefix and v1.0 without)
    options.AllowedAudiences = new List<string>
    {
        "api://1d96da07-b36b-4790-a3a8-4d2d996d1a3d",   // v2.0 tokens (custom scope like access_as_user)
        "1d96da07-b36b-4790-a3a8-4d2d996d1a3d"           // v1.0 tokens / fallback
    };
    // Functions that don't require JWT (e.g., health check, IP debug endpoint)
    options.ExcludedFunctions = new List<string> { "HealthCheck", "IpCheck" };
});

// ============================================================================
// 3. IP FILTERING CONFIGURATION
// ============================================================================
// ⚠️ LIMITATION: IP filtering via middleware does NOT work directly on Azure App Service
// because Azure Load Balancer / ARR (Application Request Routing) proxy sits between
// the client and the Function App. The middleware sees the Azure infrastructure IP
// (e.g., 4.194.122.162), NOT the real client IP (e.g., 103.235.2.17).
// X-Forwarded-For header is NOT populated by default in Azure App Service.
//
// DEBUGGING: We created /api/IpCheck endpoint to see what IP Azure actually receives.
//   Result: X-Forwarded-For = null, RemoteIpAddress = 4.194.122.162 (Azure proxy IP)
//
// SOLUTIONS:
//   1. Use Azure Front Door / Application Gateway → they add X-Forwarded-For with real client IP
//   2. Use Azure Portal → Function App → Networking → Access Restrictions (platform-level IP filtering)
//   3. The middleware below works correctly when deployed behind Azure Front Door or tested locally
builder.Services.Configure<IpFilterOptions>(options =>
{
    // Whitelist: Only these IPs can access (leave empty to allow all)
    options.AllowedIPs = new List<string>
    {
        // "203.0.113.0/24",     // Example: Office network
        // "198.51.100.42",      // Example: Specific server
    };

    // Blacklist: These IPs are always blocked (takes priority over whitelist)
    // ⚠️ Will not work without Azure Front Door — see note above
    options.BlockedIPs = new List<string>
    {
        "103.235.2.17",         // Example: Block specific IP
        // "192.168.1.0/24",     // Example: Block entire subnet
    };

    options.ExcludedFunctions = new List<string> { "HealthCheck", "IpCheck" };
});

// ============================================================================
// 4. API KEY AUTHENTICATION
// ============================================================================
// Custom API key-based authentication for service-to-service or third-party access.
// Clients pass the key via X-API-Key header or ?api_key= query parameter.
//
// USE CASE: When you want to give different clients their own keys for:
//   - Tracking usage per client
//   - Revoking access for a specific client without affecting others
//   - Different rate limits per client (combine with rate limiting middleware)
//
// NOTE: API keys are stored in code here for simplicity.
// In production, store them in:
//   - Azure Key Vault
//   - Azure App Configuration
//   - Environment variables (Function App → Configuration → Application Settings)
//
// HOW TO TEST in Insomnia:
//   Add header → X-API-Key: your-api-key-1
//   OR use query param → ?api_key=your-api-key-1
builder.Services.Configure<ApiKeyOptions>(options =>
{
    options.HeaderName = "X-API-Key";
    options.QueryParamName = "api_key";

    // Valid API keys mapped to client names
    options.ValidApiKeys = new Dictionary<string, string>
    {
        { "ak-frontend-app-2024-xyz", "Frontend App" },
        { "ak-mobile-app-2024-abc", "Mobile App" },
        { "ak-partner-api-2024-def", "Partner API" }
    };

    options.ExcludedFunctions = new List<string> { "HealthCheck", "IpCheck" };
});

// ============================================================================
// 5. REQUEST THROTTLING (Daily/Monthly Quotas per Client)
// ============================================================================
// Unlike rate limiting (short-term: X requests per N seconds), throttling enforces
// long-term quotas (e.g., 10,000 requests per day per client).
//
// HOW IT WORKS:
//   - Tracks total requests per client per day (resets at midnight UTC)
//   - Uses client name from API Key middleware (falls back to IP)
//   - Returns 429 with quota details when exceeded
//   - Adds X-Quota-Limit, X-Quota-Used, X-Quota-Remaining headers to all responses
//
// RATE LIMITING vs THROTTLING:
//   Rate Limit:  Max 10 requests per 60 seconds (burst protection)
//   Throttling:  Max 10,000 requests per day (usage cap)
//   Both can work together — rate limit prevents bursts, throttling prevents overuse
//
// ⚠️ LIMITATION: In-memory tracking, resets on app restart.
//    For production, use Azure Table Storage or Redis for persistent quota tracking.
builder.Services.Configure<ThrottleOptions>(options =>
{
    options.DefaultDailyQuota = 10000;  // Default: 10,000 requests/day

    // Per-client quota overrides (client names must match API Key middleware)
    options.ClientQuotas = new Dictionary<string, int>
    {
        { "Frontend App", 1 },     // Premium client: 50K/day
        { "Mobile App", 20000 },       // Standard client: 20K/day
        { "Partner API", 5000 }        // Limited partner: 5K/day
    };

    options.ExcludedFunctions = new List<string> { "HealthCheck", "IpCheck" };
});

// ============================================================================
// 6. REQUEST VALIDATION (SQL Injection, XSS, Path Traversal, Command Injection)
// ============================================================================
// Defense-in-depth: code-level protection in addition to WAF.
// Scans URL, query parameters, headers, and request body for attack patterns.
//
// BLOCKS:
//   - SQL Injection:     ' OR 1=1 --, UNION SELECT, DROP TABLE, etc.
//   - XSS:              <script>, javascript:, onerror=, eval(), etc.
//   - Path Traversal:   ../../etc/passwd, ..%2f, etc.
//   - Command Injection: ; rm -rf, | cat, `command`, etc.
//   - Oversized payloads, invalid content types, long URLs/headers
//
// Returns HTTP 400 (Bad Request) with attack type code
builder.Services.Configure<RequestValidationOptions>(options =>
{
    options.MaxBodySizeBytes = 1_048_576;    // 1MB max body
    options.MaxUrlLength = 2048;             // 2048 chars max URL
    options.MaxQueryStringLength = 1024;     // 1024 chars max query string
    options.MaxHeaderValueLength = 8192;     // 8KB max header value
    options.BlockSqlInjection = true;
    options.BlockXss = true;
    options.BlockPathTraversal = true;
    options.BlockCommandInjection = true;
    options.EnforceContentType = true;
    options.ExcludedFunctions = new List<string> { "HealthCheck", "IpCheck" };
});

// ============================================================================
// 7. SECURITY RESPONSE HEADERS
// ============================================================================
// Adds security headers to EVERY HTTP response automatically.
// These headers tell browsers how to handle your content securely.
//
// HEADERS ADDED:
//   Strict-Transport-Security (HSTS) → Forces HTTPS, prevents downgrade attacks
//   Content-Security-Policy (CSP)    → Controls allowed script/style/image sources
//   X-Content-Type-Options: nosniff  → Prevents MIME-type sniffing
//   X-Frame-Options: DENY            → Prevents clickjacking via iframes
//   X-XSS-Protection: 1; mode=block  → Legacy XSS filter for older browsers
//   Referrer-Policy                   → Controls referrer info leakage
//   Permissions-Policy                → Disables unused browser features
//   Cache-Control: no-store           → Prevents caching of API responses
//
// WHY: Even though this is an API (not a website), security headers are important because:
//   - API responses could be rendered in browsers (e.g., error pages)
//   - Prevents misconfigured clients from caching sensitive data
//   - Security scanners (e.g., OWASP ZAP) flag missing headers
//   - Defense-in-depth: multiple layers of protection
builder.Services.Configure<SecurityHeadersOptions>(options =>
{
    options.EnableHsts = true;
    options.HstsMaxAgeSeconds = 31536000;                    // 1 year
    options.HstsIncludeSubDomains = true;
    options.EnableCsp = true;
    options.CspPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'";
    options.EnableNoSniff = true;
    options.EnableFrameOptions = true;
    options.FrameOptionsValue = "DENY";
    options.EnableXssProtection = true;
    options.EnableReferrerPolicy = true;
    options.ReferrerPolicy = "strict-origin-when-cross-origin";
    options.EnablePermissionsPolicy = true;
    options.PermissionsPolicy = "camera=(), microphone=(), geolocation=(), payment=()";
    options.EnableNoCacheForApi = true;
});

// ============================================================================
// 8. CORS (Cross-Origin Resource Sharing)
// ============================================================================
// Controls which external domains can call your API from a browser.
// Without CORS, browsers block JavaScript from making requests to your API
// from a different domain (Same-Origin Policy).
//
// HOW IT WORKS:
//   - Browser sends Origin header with every cross-origin request
//   - Middleware checks if the origin is in the AllowedOrigins list
//   - If allowed: adds Access-Control-Allow-Origin header to response
//   - If not allowed: no CORS headers → browser blocks the response
//   - Preflight (OPTIONS) requests are handled automatically with 204
//
// IMPORTANT:
//   - "https://www.google.com" ≠ "http://www.google.com" (scheme matters)
//   - Do NOT use "*" with AllowCredentials = true (browsers reject this)
//   - host.json also has CORS headers for Azure-level config (belt + suspenders)
builder.Services.Configure<CorsOptions>(options =>
{
    options.AllowedOrigins = new List<string>
    {
        //"https://www.google.com"
        // Add more origins as needed:
        // "https://your-frontend.azurewebsites.net",
        // "http://localhost:3000",   // React dev server
        // "http://localhost:4200",   // Angular dev server
    };
    options.AllowedMethods = new List<string> { "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS" };
    options.AllowedHeaders = new List<string> { "Content-Type", "Authorization", "X-API-Key", "X-Requested-With" };
    options.ExposedHeaders = new List<string> { "X-Quota-Limit", "X-Quota-Used", "X-Quota-Remaining", "Retry-After" };
    options.AllowCredentials = true;
    options.MaxAgeSeconds = 86400; // Cache preflight for 24 hours
});

// ============================================================================
// MIDDLEWARE PIPELINE ORDER (order matters!)
// ============================================================================
// Request → CORS (preflight/headers) → Security Headers → Validation (400) → API Key (401) → JWT (401) → IP Filter (403)
//         → Rate Limit (429) → Throttle (429) → Function (200)
//
// CORS FIRST: handles preflight OPTIONS immediately, adds CORS headers to all responses
// Security Headers FIRST: runs on every response (including 400/401/403/429 errors)
//   It uses Response.OnStarting() callback so headers are added just before response is sent
// Validation first:  block malicious payloads before any processing
// API Key:           cheapest auth check, reject invalid keys
// JWT:               validate token for authenticated users
// IP Filter:         block banned IPs
// Rate Limit:        prevent short-term bursts (e.g., 10 req/min)
// Throttle last:     enforce daily quotas (e.g., 10K req/day)
builder.UseMiddleware<CorsMiddleware>();
builder.UseMiddleware<SecurityHeadersMiddleware>();
builder.UseMiddleware<RequestValidationMiddleware>();
builder.UseMiddleware<ApiKeyMiddleware>();
builder.UseMiddleware<JwtValidationMiddleware>();
builder.UseMiddleware<IpFilteringMiddleware>();
builder.UseMiddleware<RateLimitingMiddleware>();
builder.UseMiddleware<RequestThrottlingMiddleware>();

// Application Insights isn't enabled by default. See https://aka.ms/AAt8mw4.
// builder.Services
//     .AddApplicationInsightsTelemetryWorkerService()
//     .ConfigureFunctionsApplicationInsights();

builder.Build().Run();
