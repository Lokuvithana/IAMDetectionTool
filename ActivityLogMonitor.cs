using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
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

                // Prepare Kusto query
                string query = @"
                    AzureActivity
                    | where TimeGenerated > ago(30m)
                    | where CategoryValue == 'Administrative'
                    | where OperationNameValue has 'Microsoft.Authorization/roleAssignments'
                    | project 
                        EventId = _ResourceId,
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
                                        _logger.LogInformation($"📝 Processing: {iamEvent.OperationName}");
                                        await ProcessIAMEvent(iamEvent, dbHelper, riskCalculator);
                                        processedCount++;
                                    }
                                }
                                catch (Exception ex)
                                {
                                    _logger.LogError($"Error processing row: {ex.Message}");
                                }
                            }

                            _logger.LogInformation($"✅ Successfully processed {processedCount} IAM events");
                        }
                        else
                        {
                            _logger.LogInformation("ℹ️ No IAM events found in the last 10 minutes");
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
                        var requestBody = props["requestbody"]?["Properties"];

                        if (requestBody != null)
                        {
                            iamEvent.PrincipalId = requestBody["PrincipalId"]?.ToString();
                            iamEvent.RoleDefinitionId = requestBody["RoleDefinitionId"]?.ToString();
                        }

                        iamEvent.RawEventData = propertiesJson;
                    }
                    catch
                    {
                        // Properties parsing is optional
                    }
                }

                return iamEvent;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error parsing row: {ex.Message}");
                return null;
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
                    _logger.LogWarning($"🚨 HIGH RISK DETECTED!");
                    _logger.LogWarning($"   Score: {riskAssessment.RiskScore}");
                    _logger.LogWarning($"   Level: {riskAssessment.RiskLevel}");
                    _logger.LogWarning($"   Caller: {iamEvent.Caller}");
                    _logger.LogWarning($"   Reason: {riskAssessment.Reason}");
                }
                else
                {
                    _logger.LogInformation($"✅ Risk: {riskAssessment.RiskLevel} (Score: {riskAssessment.RiskScore})");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"❌ Error processing event: {ex.Message}");
            }
        }
    }
}