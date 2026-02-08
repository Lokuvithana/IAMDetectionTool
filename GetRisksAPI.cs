using System;
using System.Collections.Generic;
using Microsoft.Data.SqlClient;
using System.Net;
using System.Threading.Tasks;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace IAMDetectionTool
{
    public class GetRisksAPI
    {
        private readonly ILogger<GetRisksAPI> _logger;

        public GetRisksAPI(ILogger<GetRisksAPI> logger)
        {
            _logger = logger;
        }

        [Function("GetRisks")]
        public async Task<HttpResponseData> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", Route = "risks")] HttpRequestData req)
        {
            _logger.LogInformation("GetRisks API called");

            string? connectionString = Environment.GetEnvironmentVariable("SqlConnectionString");
            if (string.IsNullOrEmpty(connectionString))
            {
                var err = req.CreateResponse(HttpStatusCode.ServiceUnavailable);
                await err.WriteStringAsync("SqlConnectionString not configured.");
                return err;
            }

            try
            {
                var risks = await GetRiskAssessments(connectionString!);
                
                var response = req.CreateResponse(HttpStatusCode.OK);
                response.Headers.Add("Content-Type", "application/json");
                await response.WriteStringAsync(JsonConvert.SerializeObject(risks));
                
                return response;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in GetRisks: {ex.Message}");
                
                var errorResponse = req.CreateResponse(HttpStatusCode.InternalServerError);
                await errorResponse.WriteStringAsync($"Error: {ex.Message}");
                return errorResponse;
            }
        }

        private async Task<List<object>> GetRiskAssessments(string connectionString)
        {
            var results = new List<object>();

            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                await conn.OpenAsync();

                string query = @"
                    SELECT TOP 100
                        r.AssessmentId,
                        r.EventId,
                        r.RiskScore,
                        r.RiskLevel,
                        r.Reason,
                        r.IsEscalation,
                        r.IsSuspicious,
                        r.DetectedDate,
                        r.Status,
                        e.EventTime,
                        e.Caller,
                        e.PrincipalName,
                        e.RoleName,
                        e.ResourceName,
                        e.OperationName
                    FROM RiskAssessments r
                    INNER JOIN IAMEvents e ON r.EventId = e.EventId
                    ORDER BY r.DetectedDate DESC";

                using (SqlCommand cmd = new SqlCommand(query, conn))
                {
                    using (SqlDataReader reader = await cmd.ExecuteReaderAsync())
                    {
                        while (await reader.ReadAsync())
                        {
                            results.Add(new
                            {
                                assessmentId = reader["AssessmentId"],
                                eventId = reader["EventId"],
                                riskScore = reader["RiskScore"],
                                riskLevel = reader["RiskLevel"],
                                reason = reader["Reason"],
                                isEscalation = reader["IsEscalation"],
                                isSuspicious = reader["IsSuspicious"],
                                detectedDate = reader["DetectedDate"],
                                status = reader["Status"],
                                eventTime = reader["EventTime"],
                                caller = reader["Caller"],
                                principalName = reader.IsDBNull(reader.GetOrdinal("PrincipalName")) 
                                    ? null : reader["PrincipalName"],
                                roleName = reader.IsDBNull(reader.GetOrdinal("RoleName")) 
                                    ? null : reader["RoleName"],
                                resourceName = reader.IsDBNull(reader.GetOrdinal("ResourceName")) 
                                    ? null : reader["ResourceName"],
                                operationName = reader["OperationName"]
                            });
                        }
                    }
                }
            }

            return results;
        }
    }
}