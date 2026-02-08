using System;
using System.Collections.Generic;
using System.Data;
using Microsoft.Data.SqlClient;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace IAMDetectionTool
{
    public class DatabaseHelper
    {
        private readonly string _connectionString;
        private readonly ILogger _logger;

        public DatabaseHelper(string connectionString, ILogger logger)
        {
            _connectionString = connectionString;
            _logger = logger;
        }

        public async Task StoreIAMEvent(IAMEvent iamEvent)
        {
            using (SqlConnection conn = new SqlConnection(_connectionString))
            {
                await conn.OpenAsync();

                string query = @"
                    IF NOT EXISTS (SELECT 1 FROM IAMEvents WHERE EventId = @EventId)
                    BEGIN
                        INSERT INTO IAMEvents 
                        (EventId, EventTime, OperationName, Caller, CallerIpAddress, PrincipalId, 
                         PrincipalName, PrincipalType, RoleDefinitionId, RoleName, Scope, 
                         ResourceId, ResourceName, Status, StatusCode, RawEventData)
                        VALUES 
                        (@EventId, @EventTime, @OperationName, @Caller, @CallerIpAddress, @PrincipalId, 
                         @PrincipalName, @PrincipalType, @RoleDefinitionId, @RoleName, @Scope, 
                         @ResourceId, @ResourceName, @Status, @StatusCode, @RawEventData)
                    END";

                using (SqlCommand cmd = new SqlCommand(query, conn))
                {
                    cmd.Parameters.AddWithValue("@EventId", iamEvent.EventId ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@EventTime", iamEvent.EventTime);
                    cmd.Parameters.AddWithValue("@OperationName", iamEvent.OperationName ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@Caller", iamEvent.Caller ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@CallerIpAddress", iamEvent.CallerIpAddress ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@PrincipalId", iamEvent.PrincipalId ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@PrincipalName", iamEvent.PrincipalName ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@PrincipalType", iamEvent.PrincipalType ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@RoleDefinitionId", iamEvent.RoleDefinitionId ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@RoleName", iamEvent.RoleName ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@Scope", iamEvent.Scope ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@ResourceId", iamEvent.ResourceId ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@ResourceName", iamEvent.ResourceName ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@Status", iamEvent.Status ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@StatusCode", iamEvent.StatusCode ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@RawEventData", iamEvent.RawEventData ?? (object)DBNull.Value);

                    await cmd.ExecuteNonQueryAsync();
                }
            }

            _logger.LogInformation($"Stored IAM event: {iamEvent.EventId}");
        }

        public async Task<bool> CheckBaselineMatch(string? principalId, string? roleDefinitionId, string? scope)
        {
            using (SqlConnection conn = new SqlConnection(_connectionString))
            {
                await conn.OpenAsync();

                string query = @"
                    SELECT COUNT(*) FROM BaselineRoleAssignments 
                    WHERE PrincipalId = @PrincipalId 
                    AND RoleDefinitionId = @RoleDefinitionId 
                    AND Scope = @Scope 
                    AND IsApproved = 1";

                using (SqlCommand cmd = new SqlCommand(query, conn))
                {
                    cmd.Parameters.AddWithValue("@PrincipalId", principalId ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@RoleDefinitionId", roleDefinitionId ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@Scope", scope ?? (object)DBNull.Value);

                    object? scalar = await cmd.ExecuteScalarAsync();
                    int count = scalar != null ? (int)scalar : 0;
                    return count > 0;
                }
            }
        }

        public async Task<int> GetPrivilegedRoleWeight(string? roleDefinitionId)
        {
            using (SqlConnection conn = new SqlConnection(_connectionString))
            {
                await conn.OpenAsync();

                string query = @"
                    SELECT RiskWeight FROM PrivilegedRoles 
                    WHERE RoleDefinitionId = @RoleDefinitionId 
                    AND IsActive = 1";

                using (SqlCommand cmd = new SqlCommand(query, conn))
                {
                    cmd.Parameters.AddWithValue("@RoleDefinitionId", roleDefinitionId ?? (object)DBNull.Value);

                    object? result = await cmd.ExecuteScalarAsync();
                    return result is int i ? i : 0;
                }
            }
        }

        public async Task<bool> IsKnownAdministrator(string? email)
        {
            using (SqlConnection conn = new SqlConnection(_connectionString))
            {
                await conn.OpenAsync();

                string query = @"
                    SELECT COUNT(*) FROM ApprovedAdministrators 
                    WHERE Email = @Email 
                    AND IsActive = 1";

                using (SqlCommand cmd = new SqlCommand(query, conn))
                {
                    cmd.Parameters.AddWithValue("@Email", email ?? (object)DBNull.Value);

                    object? scalar = await cmd.ExecuteScalarAsync();
                    int count = scalar != null ? (int)scalar : 0;
                    return count > 0;
                }
            }
        }

        public async Task StoreRiskAssessment(string? eventId, RiskAssessmentResult assessment)
        {
            using (SqlConnection conn = new SqlConnection(_connectionString))
            {
                await conn.OpenAsync();

                string query = @"
                    INSERT INTO RiskAssessments 
                    (EventId, RiskScore, RiskLevel, Reason, IsBaselineMatch, IsEscalation, 
                     IsSuspicious, RequiresApproval, Status)
                    VALUES 
                    (@EventId, @RiskScore, @RiskLevel, @Reason, @IsBaselineMatch, @IsEscalation, 
                     @IsSuspicious, @RequiresApproval, @Status)";

                using (SqlCommand cmd = new SqlCommand(query, conn))
                {
                    cmd.Parameters.AddWithValue("@EventId", eventId ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@RiskScore", assessment.RiskScore);
                    cmd.Parameters.AddWithValue("@RiskLevel", assessment.RiskLevel);
                    cmd.Parameters.AddWithValue("@Reason", assessment.Reason ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@IsBaselineMatch", assessment.IsBaselineMatch);
                    cmd.Parameters.AddWithValue("@IsEscalation", assessment.IsEscalation);
                    cmd.Parameters.AddWithValue("@IsSuspicious", assessment.IsSuspicious);
                    cmd.Parameters.AddWithValue("@RequiresApproval", assessment.RequiresApproval);
                    cmd.Parameters.AddWithValue("@Status", "Pending");

                    await cmd.ExecuteNonQueryAsync();
                }
            }

            _logger.LogInformation($"Stored risk assessment for event: {eventId}");
        }

        public async Task StoreBaselineAssignment(BaselineAssignment assignment)
        {
            using (SqlConnection conn = new SqlConnection(_connectionString))
            {
                await conn.OpenAsync();

                string query = @"
                    MERGE BaselineRoleAssignments AS target
                    USING (SELECT @AssignmentId AS AssignmentId) AS source
                    ON target.AssignmentId = source.AssignmentId
                    WHEN MATCHED THEN
                        UPDATE SET LastVerified = GETDATE()
                    WHEN NOT MATCHED THEN
                        INSERT (AssignmentId, PrincipalId, PrincipalName, PrincipalType, 
                                RoleDefinitionId, RoleName, Scope, AssignedDate, LastVerified, IsApproved)
                        VALUES (@AssignmentId, @PrincipalId, @PrincipalName, @PrincipalType, 
                                @RoleDefinitionId, @RoleName, @Scope, @AssignedDate, GETDATE(), 1);";

                using (SqlCommand cmd = new SqlCommand(query, conn))
                {
                    cmd.Parameters.AddWithValue("@AssignmentId", assignment.AssignmentId);
                    cmd.Parameters.AddWithValue("@PrincipalId", assignment.PrincipalId ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@PrincipalName", assignment.PrincipalName ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@PrincipalType", assignment.PrincipalType ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@RoleDefinitionId", assignment.RoleDefinitionId ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@RoleName", assignment.RoleName ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@Scope", assignment.Scope ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@AssignedDate", assignment.AssignedDate);

                    await cmd.ExecuteNonQueryAsync();
                }
            }
        }
    }
}