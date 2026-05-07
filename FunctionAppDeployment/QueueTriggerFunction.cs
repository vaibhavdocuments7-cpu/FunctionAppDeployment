using System.Threading.Tasks;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace FunctionAppDeployment
{
    public class QueueTriggerFunction
    {
        private readonly ILogger<QueueTriggerFunction> _logger;

        public QueueTriggerFunction(ILogger<QueueTriggerFunction> logger)
        {
            _logger = logger;
        }

        [Function("QueueTriggerFunction")]
        public async Task Run(
    [QueueTrigger("vaibhavqueue", Connection = "AzureWebJobsStorage")] BinaryData message)
        {
            try
            {
                var msg = message.ToString();

                _logger.LogInformation($"Queue message received: {msg}");

                await Task.Delay(100);

                _logger.LogInformation("Processing completed.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Queue processing failed");
                throw;
            }
        }
    }
}