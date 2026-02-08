using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.Authorization;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace IAMDetectionTool
{
    public class ActivityLogMonitor
    {
        private readonly ILogger<ActivityLogMonitor> _logger;
        private static readonly HttpClient _httpClient = new HttpClient();

        public ActivityLogMonitor(ILogger<ActivityLogMonitor> logger)
        {
            _logger = logger;
        }

        [Function("ActivityLogMonitor")]
        public async Task Run(
            [TimerTrigger("0 */5 * * * *")] TimerInfo timer)
        {
            _logger.LogInformation($"=== Activity Log Monitor Started at: {DateTime.UtcNow} ===");

            string? connectionString = Environment.GetEnvironmentVariable("SqlConnectionString");
            string? workspaceId = Environment.GetEnvironmentVariable("LogAnalyticsWorkspaceId");

            if (string.IsNullOrEmpty(connectionString))
            {
                _logger.LogError("❌ SQL Connection String not found!");
                return;
            }

            if (string.IsNullOrEmpty(workspaceId))
            {
                _logger.LogError("❌ LogAnalyticsWorkspaceId not found!");
                return;
            }

            try
            {
                var dbHelper = new DatabaseHelper(connectionString, _logger);
                var riskCalculator = new RiskCalculator(dbHelper, _logger);

                await QueryAndProcessActivityLogs(workspaceId, dbHelper, riskCalculator);
            }
            catch (Exception ex)
            {
                _logger.LogError($"❌ Error in ActivityLogMonitor: {ex.Message}");
                _logger.LogError($"Stack trace: {ex.StackTrace}");
            }
        }

        private async Task QueryAndProcessActivityLogs(
            string workspaceId,
            DatabaseHelper dbHelper,
            RiskCalculator riskCalculator)
        {
            try
            {
                _logger.LogInformation($"🔍 Querying Log Analytics Workspace: {workspaceId}");

                // Get access token using Managed Identity
                var credential = new DefaultAzureCredential();
                var tokenRequestContext = new TokenRequestContext(
                    new[] { "https://api.loganalytics.io/.default" });
                
                _logger.LogInformation("🔑 Obtaining access token...");
                var token = await credential.GetTokenAsync(tokenRequestContext);

                // Create ARM client for role assignment enrichment
                var armClient = new ArmClient(credential);

                // Prepare Kusto query - extended to 30 minutes for better detection
                string query = @"
                    AzureActivity
                    | where TimeGenerated > ago(30m)
                    | where CategoryValue == 'Administrative'
                    | where OperationNameValue has 'Microsoft.Authorization/roleAssignments'
                    | project 
                        EventId = CorrelationId,
                        EventTime = TimeGenerated,
                        OperationName = OperationNameValue,
                        Caller,
                        CallerIpAddress,
                        Status = ActivityStatusValue,
                        SubscriptionId,
                        ResourceGroup,
                        ResourceId = _ResourceId,
                        Properties
                    | order by EventTime desc
                ";

                // Call Log Analytics REST API
                var url = $"https://api.loganalytics.io/v1/workspaces/{workspaceId}/query";
                var requestBody = new { query = query };
                var content = new StringContent(
                    JsonConvert.SerializeObject(requestBody),
                    System.Text.Encoding.UTF8,
                    "application/json");

                _httpClient.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", token.Token);

                _logger.LogInformation("📊 Executing query via REST API...");
                var response = await _httpClient.PostAsync(url, content);
                var responseContent = await response.Content.ReadAsStringAsync(); 

                if (response.IsSuccessStatusCode)
                {
                    var result = JObject.Parse(responseContent);
                    var tables = result["tables"] as JArray;

                    if (tables != null && tables.Count > 0)
                    {
                        var table = tables[0] as JObject;
                        var rows = table?["rows"] as JArray;
                        var columns = table?["columns"] as JArray;

                        int rowCount = rows?.Count ?? 0;
                        _logger.LogInformation($"✅ Query successful! Found {rowCount} events");

                        if (rows != null && columns != null && rowCount > 0)
                        {
                            int processedCount = 0;
                            foreach (JArray row in rows)
                            {
                                try
                                {
                                    var iamEvent = ParseLogRow(row, columns);

                                    if (iamEvent != null)
                                    {
                                        _logger.LogInformation($"📝 Processing: {iamEvent.OperationName} by {iamEvent.Caller}");
                                        
                                        // Enrich with role assignment details
                                        await EnrichWithRoleDetails(iamEvent, armClient);
                                        
                                        await ProcessIAMEvent(iamEvent, dbHelper, riskCalculator);
                                        processedCount++;
                                    }
                                }
                                catch (Exception ex)
                                {
                                    _logger.LogError($"❌ Error processing row: {ex.Message}");
                                }
                            }

                            _logger.LogInformation($"✅ Successfully processed {processedCount} IAM events");
                        }
                        else
                        {
                            _logger.LogInformation("ℹ️ No IAM events found in the last 30 minutes");
                        }
                    }
                    else
                    {
                        _logger.LogInformation("ℹ️ No data returned from query");
                    }
                }
                else
                {
                    _logger.LogError($"❌ Query failed: {response.StatusCode}");
                    _logger.LogError($"Response: {responseContent}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"❌ Error querying logs: {ex.Message}");
                _logger.LogError($"Stack trace: {ex.StackTrace}");
                throw;
            }
        }

        private IAMEvent? ParseLogRow(JArray row, JArray columns)
        {
            try
            {
                var iamEvent = new IAMEvent
                {
                    EventId = GetColumnValue(row, columns, "EventId") ?? Guid.NewGuid().ToString(),
                    EventTime = DateTime.Parse(GetColumnValue(row, columns, "EventTime") ?? DateTime.UtcNow.ToString()),
                    OperationName = GetColumnValue(row, columns, "OperationName"),
                    Caller = GetColumnValue(row, columns, "Caller"),
                    CallerIpAddress = GetColumnValue(row, columns, "CallerIpAddress"),
                    Status = GetColumnValue(row, columns, "Status"),
                    ResourceId = GetColumnValue(row, columns, "ResourceId"),
                    Scope = GetColumnValue(row, columns, "ResourceId")
                };

                // Try to parse Properties for additional details
                string? propertiesJson = GetColumnValue(row, columns, "Properties");
                if (!string.IsNullOrEmpty(propertiesJson))
                {
                    try
                    {
                        var props = JObject.Parse(propertiesJson);
                        
                        // Try different paths to get role assignment details
                        var requestBody = props["requestbody"]?["Properties"];
                        if (requestBody != null)
                        {
                            iamEvent.PrincipalId = requestBody["PrincipalId"]?.ToString();
                            iamEvent.RoleDefinitionId = requestBody["RoleDefinitionId"]?.ToString();
                        }

                        // Extract status code
                        iamEvent.StatusCode = props["statusCode"]?.ToString();

                        iamEvent.RawEventData = propertiesJson;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"⚠️ Could not parse properties: {ex.Message}");
                    }
                }

                return iamEvent;
            }
            catch (Exception ex)
            {
                _logger.LogError($"❌ Error parsing row: {ex.Message}");
                return null;
            }
        }

        private async Task EnrichWithRoleDetails(IAMEvent iamEvent, ArmClient armClient)
        {
            try
            {
                // Only enrich for 'write' operations (new assignments)
                if (string.IsNullOrEmpty(iamEvent.ResourceId) || 
                    !iamEvent.OperationName?.Contains("write", StringComparison.OrdinalIgnoreCase) == true)
                {
                    return;
                }

                _logger.LogInformation($"🔍 Enriching event with role assignment details...");

                // Parse the resource ID to get the role assignment
                var roleAssignmentId = new Azure.Core.ResourceIdentifier(iamEvent.ResourceId);
                var roleAssignment = armClient.GetRoleAssignmentResource(roleAssignmentId);

                // Fetch the role assignment details
                var roleAssignmentData = await roleAssignment.GetAsync();

                // Extract role assignment details
                iamEvent.PrincipalId = roleAssignmentData.Value.Data.PrincipalId.ToString();
                iamEvent.PrincipalType = roleAssignmentData.Value.Data.PrincipalType.ToString();
                iamEvent.RoleDefinitionId = roleAssignmentData.Value.Data.RoleDefinitionId.ToString();
                iamEvent.Scope = roleAssignmentData.Value.Data.Scope;

                // Get role name from role definition ID
                var roleName = GetRoleName(roleAssignmentData.Value.Data.RoleDefinitionId.ToString());
                iamEvent.RoleName = roleName;

                // Extract resource name from scope
                if (!string.IsNullOrEmpty(iamEvent.Scope))
                {
                    var scopeParts = iamEvent.Scope.Split('/');
                    iamEvent.ResourceName = scopeParts.Length > 0 ? scopeParts[scopeParts.Length - 1] : null;
                }

                // Set principal name as type + short ID for now
                if (!string.IsNullOrEmpty(iamEvent.PrincipalId))
                {
                    var shortId = iamEvent.PrincipalId.Length > 8 
                        ? iamEvent.PrincipalId.Substring(0, 8) 
                        : iamEvent.PrincipalId;
                    iamEvent.PrincipalName = $"{iamEvent.PrincipalType}: {shortId}...";
                }

                _logger.LogInformation($"✅ Enriched - Role: {iamEvent.RoleName}, Principal: {iamEvent.PrincipalType}, Scope: {iamEvent.ResourceName}");
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"⚠️ Could not enrich with role details: {ex.Message}");
                // Don't fail the entire event processing if enrichment fails
                // We'll still have basic data from the activity log
            }
        }

        private string GetRoleName(string roleDefinitionId)
        {
            // Common Azure built-in role IDs to names mapping
            var knownRoles = new Dictionary<string, string>
            {
                { "8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "Owner" },
                { "b24988ac-6180-42a0-ab88-20f7382dd24c", "Contributor" },
                { "acdd72a7-3385-48ef-bd42-f606fba81ae7", "Reader" },
                { "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9", "User Access Administrator" },
                { "f58310d9-a9f6-439a-9e8d-f62e7b41a168", "Role Based Access Control Administrator" },
                { "ba92f5b4-2d11-453d-a403-e96b0029c9fe", "Storage Blob Data Contributor" },
                { "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1", "Storage Blob Data Reader" },
                { "b7e6dc6d-f1e8-4753-8033-0f276bb0955b", "Storage Blob Data Owner" }
            };

            try
            {
                // Extract just the GUID from the role definition ID
                var roleGuid = roleDefinitionId.Split('/').Last().ToLower();

                // Check if it's a known role
                if (knownRoles.TryGetValue(roleGuid, out var roleName))
                {
                    return roleName;
                }

                return $"Custom Role ({roleGuid.Substring(0, 8)}...)";
            }
            catch
            {
                return "Unknown Role";
            }
        }

        private string? GetColumnValue(JArray row, JArray columns, string columnName)
        {
            for (int i = 0; i < columns.Count; i++)
            {
                var column = columns[i] as JObject;
                if (column?["name"]?.ToString()?.Equals(columnName, StringComparison.OrdinalIgnoreCase) == true)
                {
                    return row[i]?.ToString();
                }
            }
            return null;
        }

        private async Task ProcessIAMEvent(
            IAMEvent iamEvent,
            DatabaseHelper dbHelper,
            RiskCalculator riskCalculator)
        {
            try
            {
                _logger.LogInformation($"💾 Storing event: {iamEvent.EventId}");
                await dbHelper.StoreIAMEvent(iamEvent);

                _logger.LogInformation($"⚖️ Calculating risk...");
                var riskAssessment = await riskCalculator.CalculateRisk(iamEvent);

                _logger.LogInformation($"💾 Storing risk assessment...");
                await dbHelper.StoreRiskAssessment(iamEvent.EventId!, riskAssessment);

                if (riskAssessment.RiskScore >= 60)
                {
                    _logger.LogWarning($"");
                    _logger.LogWarning($"🚨🚨🚨 HIGH RISK EVENT DETECTED! 🚨🚨🚨");
                    _logger.LogWarning($"   Score: {riskAssessment.RiskScore}");
                    _logger.LogWarning($"   Level: {riskAssessment.RiskLevel}");
                    _logger.LogWarning($"   Caller: {iamEvent.Caller}");
                    _logger.LogWarning($"   Role: {iamEvent.RoleName ?? "Unknown"}");
                    _logger.LogWarning($"   Principal: {iamEvent.PrincipalName ?? iamEvent.PrincipalId ?? "Unknown"}");
                    _logger.LogWarning($"   Operation: {iamEvent.OperationName}");
                    _logger.LogWarning($"   Reason: {riskAssessment.Reason}");
                    _logger.LogWarning($"   EventId: {iamEvent.EventId}");
                    _logger.LogWarning($"🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨🚨");
                    _logger.LogWarning($"");
                }
                else
                {
                    _logger.LogInformation($"✅ Risk: {riskAssessment.RiskLevel} (Score: {riskAssessment.RiskScore})");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"❌ Error processing event: {ex.Message}");
                _logger.LogError($"Stack trace: {ex.StackTrace}");
            }
        }
    }
}