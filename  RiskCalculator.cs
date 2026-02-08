using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace IAMDetectionTool
{
    public class RiskCalculator
    {
        private readonly DatabaseHelper _dbHelper;
        private readonly ILogger _logger;

        public RiskCalculator(DatabaseHelper dbHelper, ILogger logger)
        {
            _dbHelper = dbHelper;
            _logger = logger;
        }

        public async Task<RiskAssessmentResult> CalculateRisk(IAMEvent iamEvent)
        {
            int riskScore = 0;
            List<string> riskReasons = new List<string>();
            bool isEscalation = false;
            bool isBaselineMatch = false;
            bool isSuspicious = false;

            // Check 1: Baseline match
            isBaselineMatch = await _dbHelper.CheckBaselineMatch(
                iamEvent.PrincipalId, 
                iamEvent.RoleDefinitionId, 
                iamEvent.Scope);

            if (!isBaselineMatch)
            {
                riskScore += 40;
                riskReasons.Add("Role assignment not found in approved baseline");
                isSuspicious = true;
            }

            // Check 2: Privileged role
            int roleWeight = await _dbHelper.GetPrivilegedRoleWeight(iamEvent.RoleDefinitionId);
            if (roleWeight > 0)
            {
                riskScore += roleWeight;
                riskReasons.Add($"Assignment of privileged role (weight: {roleWeight})");
                isEscalation = true;
            }

            // Check 3: Outside business hours
            if (IsOutsideBusinessHours(iamEvent.EventTime))
            {
                riskScore += 15;
                riskReasons.Add("Assignment occurred outside business hours");
            }

            // Check 4: Broad scope (subscription level)
            if (IsBroadScope(iamEvent.Scope))
            {
                riskScore += 20;
                riskReasons.Add("Assignment at broad scope (subscription or management group level)");
            }

            // Check 5: Unknown administrator
            bool isKnownAdmin = await _dbHelper.IsKnownAdministrator(iamEvent.Caller);
            if (!isKnownAdmin && !string.IsNullOrEmpty(iamEvent.Caller))
            {
                riskScore += 25;
                riskReasons.Add("Assignment performed by non-approved administrator");
                isSuspicious = true;
            }

            // Check 6: Failed operation
            if (iamEvent.Status?.ToLower() == "failed")
            {
                riskScore += 10;
                riskReasons.Add("Failed role assignment attempt detected");
            }

            // Determine risk level
            string riskLevel = riskScore switch
            {
                >= 80 => "Critical",
                >= 60 => "High",
                >= 40 => "Medium",
                _ => "Low"
            };

            var result = new RiskAssessmentResult
            {
                RiskScore = riskScore,
                RiskLevel = riskLevel,
                Reason = string.Join("; ", riskReasons),
                IsBaselineMatch = isBaselineMatch,
                IsEscalation = isEscalation,
                IsSuspicious = isSuspicious,
                RequiresApproval = riskScore >= 60
            };

            _logger.LogInformation($"Risk calculated - Score: {riskScore}, Level: {riskLevel}");

            return result;
        }

        private bool IsOutsideBusinessHours(DateTime eventTime)
        {
            // Convert to local time if needed
            DateTime localTime = eventTime.ToLocalTime();

            // Weekend
            if (localTime.DayOfWeek == DayOfWeek.Saturday || 
                localTime.DayOfWeek == DayOfWeek.Sunday)
                return true;

            // Outside 9 AM - 6 PM
            if (localTime.Hour < 9 || localTime.Hour >= 18)
                return true;

            return false;
        }

        private bool IsBroadScope(string? scope)
        {
            if (string.IsNullOrEmpty(scope))
                return false;

            // Check if scope is at subscription or management group level
            // (not at resource group or resource level)
            scope = scope.ToLower();
            
            if (scope.Contains("/subscriptions/") && !scope.Contains("/resourcegroups/"))
                return true;

            if (scope.Contains("/managementgroups/"))
                return true;

            return false;
        }
    }
}