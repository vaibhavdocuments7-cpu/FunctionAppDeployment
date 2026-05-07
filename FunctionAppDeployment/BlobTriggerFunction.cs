using System;
using Azure.Core.Diagnostics;
using Azure.Identity;
using Azure.Storage.Queues;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using System.Diagnostics.Tracing;

namespace FunctionAppDeployment
{
    public class BlobTriggerFunction
    {
        private readonly ILogger<BlobTriggerFunction> _logger;

        // ✅ Create listener ONCE (static)
        private static readonly AzureEventSourceListener _listener =
            new AzureEventSourceListener((eventArgs, message) =>
            {
                Console.WriteLine(message);
            }, EventLevel.Verbose);

        public BlobTriggerFunction(ILogger<BlobTriggerFunction> logger)
        {
            _logger = logger;
        }

        [Function("BlobTriggerFunction")]
        public async Task Run(
            [BlobTrigger("vaibhav/{name}", Connection = "AzureWebJobsStorage")] string inputBlob,
            string name)
        {
            _logger.LogInformation($"Processing blob: {name}");

            try
            {
                string queueName = "vaibhavqueue";
                var queueUri = new Uri($"https://adlsg2qastorage2.queue.core.windows.net/{queueName}");
                // ✅ Uses Managed Identity / CLI automatically
                var credential = new DefaultAzureCredential();
                var queueClient = new QueueClient(queueUri, credential);
                await queueClient.CreateIfNotExistsAsync();

                string message = $"Processed Queue: {name}";
                // ✅ No need for manual Base64 encoding
                await queueClient.SendMessageAsync(
                Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(message))
                );

                _logger.LogInformation("Message sent to queue via Managed Identity");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error while sending message to queue");
                throw; // important for retry behavior
            }
        }
    }
}