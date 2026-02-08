using System;

namespace IAMDetectionTool
{
    public class IAMEvent
    {
        public string? EventId { get; set; }
        public DateTime EventTime { get; set; }
        public string? OperationName { get; set; }
        public string? Caller { get; set; }
        public string? CallerIpAddress { get; set; }
        public string? PrincipalId { get; set; }
        public string? PrincipalName { get; set; }
        public string? PrincipalType { get; set; }
        public string? RoleDefinitionId { get; set; }
        public string? RoleName { get; set; }
        public string? Scope { get; set; }
        public string? ResourceId { get; set; }
        public string? ResourceName { get; set; }
        public string? Status { get; set; }
        public string? StatusCode { get; set; }
        public string? RawEventData { get; set; }
    }

    public class RiskAssessmentResult
    {
        public int RiskScore { get; set; }
        public string? RiskLevel { get; set; }
        public string? Reason { get; set; }
        public bool IsBaselineMatch { get; set; }
        public bool IsEscalation { get; set; }
        public bool IsSuspicious { get; set; }
        public bool RequiresApproval { get; set; }
    }

    public class BaselineAssignment
    {
        public string? AssignmentId { get; set; }
        public string? PrincipalId { get; set; }
        public string? PrincipalName { get; set; }
        public string? PrincipalType { get; set; }
        public string? RoleDefinitionId { get; set; }
        public string? RoleName { get; set; }
        public string? Scope { get; set; }
        public DateTime AssignedDate { get; set; }
    }
}
