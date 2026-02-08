using System;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.Authorization;
using Azure.ResourceManager.Resources;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace IAMDetectionTool
{
    public class BaselineCollector
    {
        private readonly ILogger<BaselineCollector> _logger;

        public BaselineCollector(ILogger<BaselineCollector> logger)
        {
            _logger = logger;
        }

        [Function("BaselineCollector")]
        public async Task Run(
            [TimerTrigger("0 0 2 * * *")] TimerInfo timer) // Run daily at 2 AM
        {
            _logger.LogInformation($"Baseline Collector executed at: {DateTime.Now}");

            string? connectionString = Environment.GetEnvironmentVariable("SqlConnectionString");
            string? subscriptionId = Environment.GetEnvironmentVariable("SubscriptionId");

            if (string.IsNullOrEmpty(connectionString) || string.IsNullOrEmpty(subscriptionId))
            {
                _logger.LogError("Required environment variables not found");
                return;
            }

            try
            {
                var dbHelper = new DatabaseHelper(connectionString, _logger);
                await CollectRoleAssignments(subscriptionId, dbHelper);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in BaselineCollector: {ex.Message}");
                throw;
            }
        }

        private async Task CollectRoleAssignments(string subscriptionId, DatabaseHelper dbHelper)
        {
            try
            {
                var credential = new DefaultAzureCredential();
                var armClient = new ArmClient(credential);

                var subscription = armClient.GetSubscriptionResource(
                    new ResourceIdentifier($"/subscriptions/{subscriptionId}"));

                _logger.LogInformation($"Collecting role assignments for subscription: {subscriptionId}");

                int count = 0;
                await foreach (var roleAssignment in subscription.GetRoleAssignments().GetAllAsync())
                {
                    var assignment = new BaselineAssignment
                    {
                        AssignmentId = roleAssignment.Id.ToString(),
                        PrincipalId = roleAssignment.Data.PrincipalId.ToString(),
                        PrincipalType = roleAssignment.Data.PrincipalType.ToString(),
                        RoleDefinitionId = roleAssignment.Data.RoleDefinitionId.ToString(),
                        Scope = roleAssignment.Data.Scope,
                        AssignedDate = roleAssignment.Data.CreatedOn?.DateTime ?? DateTime.UtcNow
                    };

                    await dbHelper.StoreBaselineAssignment(assignment);
                    count++;
                }

                _logger.LogInformation($"Collected {count} role assignments to baseline");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error collecting role assignments: {ex.Message}");
                throw;
            }
        }
    }
}