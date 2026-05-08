using FunctionAppDeployment.Middleware;
using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = FunctionsApplication.CreateBuilder(args);

builder.ConfigureFunctionsWebApplication();

// Rate Limiting Configuration
builder.Services.Configure<RateLimitOptions>(options =>
{
    options.PermitLimit = 3;       // Max 10 requests
    options.WindowInSeconds = 10;   // Per 60-second window
    options.QueueLimit = 0;         // No queuing — reject immediately
});

// JWT Validation Configuration (Azure AD / Entra ID)
builder.Services.Configure<JwtValidationOptions>(options =>
{
    options.TenantId = Environment.GetEnvironmentVariable("AzureAd__TenantId") ?? "79e7043b-2d89-4454-9f07-1d8ceb3f0399";
    options.ClientId = Environment.GetEnvironmentVariable("AzureAd__ClientId") ?? "7e754dae-6f36-42be-a2ee-9f1db190ed84";
    options.Instance = "https://login.microsoftonline.com/";
    options.AllowedAudiences = new List<string>
    {
        "api://7e754dae-6f36-42be-a2ee-9f1db190ed84",
        "7e754dae-6f36-42be-a2ee-9f1db190ed84"
    };
    // Functions that don't require JWT (e.g., health check)
    options.ExcludedFunctions = new List<string> { "HealthCheck" };
});

// Middleware order matters! JWT runs first, then rate limiting
builder.UseMiddleware<JwtValidationMiddleware>();
builder.UseMiddleware<RateLimitingMiddleware>();

// Application Insights isn't enabled by default. See https://aka.ms/AAt8mw4.
// builder.Services
//     .AddApplicationInsightsTelemetryWorkerService()
//     .ConfigureFunctionsApplicationInsights();

builder.Build().Run();
