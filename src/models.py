"""Data models for Semgrep API responses and SARIF output."""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from enum import Enum

from pydantic import BaseModel, Field


# Semgrep V1 API Models
class SemgrepV1Location(BaseModel):
    """Location information from Semgrep V1 API."""
    column: Optional[int] = None
    end_column: Optional[int] = None
    end_line: Optional[int] = None
    file_path: str
    line: int


class SemgrepV1Rule(BaseModel):
    """Rule information from Semgrep V1 API."""
    category: Optional[str] = None
    confidence: Optional[str] = None
    cwe_names: Optional[List[str]] = None
    message: str
    name: str
    owasp_names: Optional[List[str]] = None
    subcategories: Optional[List[str]] = None
    vulnerability_classes: Optional[List[str]] = None


class SemgrepV1Repository(BaseModel):
    """Repository information from Semgrep V1 API."""
    name: str
    url: Optional[str] = None


class SemgrepV1Finding(BaseModel):
    """Individual finding from Semgrep V1 API."""
    id: int
    categories: Optional[List[str]] = None
    confidence: Optional[str] = None
    created_at: Optional[str] = None
    location: SemgrepV1Location
    rule: SemgrepV1Rule
    rule_message: str
    rule_name: str
    severity: str
    state: Optional[str] = None
    status: Optional[str] = None
    repository: Optional[SemgrepV1Repository] = None
    ref: Optional[str] = None
    match_based_id: Optional[str] = None
    syntactic_id: Optional[str] = None
    triage_state: Optional[str] = None


class SemgrepV1Response(BaseModel):
    """Response from Semgrep V1 findings API."""
    findings: List[SemgrepV1Finding]


# Semgrep V2 API Models
class SemgrepV2Position(BaseModel):
    """Position information in V2 API."""
    line: Optional[str] = None
    col: Optional[str] = None
    offset: Optional[str] = None


class SemgrepV2Location(BaseModel):
    """Location information in V2 API."""
    path: str
    start: SemgrepV2Position
    end: SemgrepV2Position
    locationUrl: Optional[str] = None


class SemgrepV2DataflowTrace(BaseModel):
    """Dataflow trace information from V2 API."""
    taintSource: Optional[List[SemgrepV2Location]] = None
    intermediateVars: Optional[List[SemgrepV2Location]] = None
    taintSink: Optional[List[SemgrepV2Location]] = None


class SemgrepV2Repository(BaseModel):
    """Repository information from V2 API."""
    name: str
    id: Optional[str] = None
    type: Optional[str] = None


class SemgrepV2Severity(str, Enum):
    """Severity levels in V2 API."""
    CRITICAL = "SEVERITY_CRITICAL"
    HIGH = "SEVERITY_HIGH"
    MEDIUM = "SEVERITY_MEDIUM"
    LOW = "SEVERITY_LOW"
    INFO = "SEVERITY_INFO"


class SemgrepV2Confidence(str, Enum):
    """Confidence levels in V2 API."""
    HIGH = "CONFIDENCE_HIGH"
    MEDIUM = "CONFIDENCE_MEDIUM"
    LOW = "CONFIDENCE_LOW"


class SemgrepV2AutoTriageVerdict(str, Enum):
    """Auto-triage verdict values."""
    TRUE_POSITIVE = "VERDICT_TRUE_POSITIVE"
    FALSE_POSITIVE = "VERDICT_FALSE_POSITIVE"
    UNKNOWN = "VERDICT_UNKNOWN"


class SemgrepV2AutoTriage(BaseModel):
    """Auto-triage information from V2 API."""
    verdict: Optional[SemgrepV2AutoTriageVerdict] = None
    reason: Optional[str] = None


class SemgrepV2Remediation(BaseModel):
    """Remediation information from V2 API."""
    autofix: Optional[Dict[str, Any]] = None
    guidance: Optional[Dict[str, Any]] = None


class SemgrepV2Finding(BaseModel):
    """Detailed finding from Semgrep V2 API."""
    id: str
    createdAt: Optional[str] = None
    ref: Optional[str] = None
    syntacticId: Optional[str] = None
    matchBasedId: Optional[str] = None
    ruleId: Optional[str] = None
    repository: Optional[SemgrepV2Repository] = None
    triageState: Optional[str] = None
    triageReason: Optional[str] = None
    relevantSince: Optional[str] = None
    note: Optional[str] = None
    autotriage: Optional[SemgrepV2AutoTriage] = None
    lineOfCodeUrl: Optional[str] = None
    codeSnippet: Optional[str] = None
    dataflowTrace: Optional[SemgrepV2DataflowTrace] = None
    commitUrl: Optional[str] = None
    remediation: Optional[SemgrepV2Remediation] = None
    filePath: str
    line: int
    endLine: Optional[int] = None
    column: Optional[int] = None
    endColumn: Optional[int] = None
    severity: Optional[SemgrepV2Severity] = None
    message: str
    rulePath: Optional[str] = None
    confidence: Optional[SemgrepV2Confidence] = None
    ruleUrl: Optional[str] = None
    ruleReferences: Optional[List[str]] = None
    ruleCweNames: Optional[List[str]] = None
    ruleOwaspNames: Optional[List[str]] = None
    category: Optional[str] = None
    subcategories: Optional[List[str]] = None


# SARIF Models
class SARIFLevel(str, Enum):
    """SARIF result levels."""
    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"
    INFO = "info"


# New SARIF invocation models
class SARIFToolExecutionNotification(BaseModel):
    """SARIF tool execution notification."""
    descriptor: Dict[str, str]  # Contains "id" field
    level: str  # "warning", "error", etc.
    message: "SARIFMessage"


class SARIFInvocation(BaseModel):
    """SARIF invocation information."""
    executionSuccessful: bool
    toolExecutionNotifications: Optional[List[SARIFToolExecutionNotification]] = None


class SARIFArtifactLocation(BaseModel):
    """SARIF artifact location."""
    uri: str
    uriBaseId: Optional[str] = None


class SARIFSnippet(BaseModel):
    """SARIF snippet information."""
    text: str


class SARIFRegion(BaseModel):
    """SARIF region information."""
    endColumn: Optional[int] = None
    endLine: Optional[int] = None
    snippet: Optional[SARIFSnippet] = None
    startColumn: Optional[int] = None
    startLine: int


class SARIFPhysicalLocation(BaseModel):
    """SARIF physical location."""
    artifactLocation: SARIFArtifactLocation
    region: Optional[SARIFRegion] = None


class SARIFLocation(BaseModel):
    """SARIF location."""
    physicalLocation: SARIFPhysicalLocation
    message: Optional[Dict[str, str]] = None


class SARIFMessage(BaseModel):
    """SARIF message."""
    text: str


class SARIFThreadFlowLocation(BaseModel):
    """SARIF thread flow location."""
    location: SARIFLocation
    kinds: Optional[List[str]] = None
    nestingLevel: Optional[int] = None
    executionOrder: Optional[int] = None
    importance: Optional[str] = None


class SARIFThreadFlow(BaseModel):
    """SARIF thread flow."""
    locations: List[SARIFThreadFlowLocation]
    message: Optional[SARIFMessage] = None


class SARIFCodeFlow(BaseModel):
    """SARIF code flow."""
    threadFlows: List[SARIFThreadFlow]
    message: Optional[SARIFMessage] = None


class SARIFTaxon(BaseModel):
    """SARIF taxon for CWE/OWASP classifications."""
    id: str
    name: Optional[str] = None
    shortDescription: Optional[SARIFMessage] = None


class SARIFTaxonomy(BaseModel):
    """SARIF taxonomy."""
    name: str
    guid: Optional[str] = None
    taxa: List[SARIFTaxon]


class SARIFRule(BaseModel):
    """SARIF rule definition."""
    id: str
    name: Optional[str] = None
    shortDescription: Optional[SARIFMessage] = None
    fullDescription: Optional[SARIFMessage] = None
    helpUri: Optional[str] = None
    messageStrings: Optional[Dict[str, SARIFMessage]] = None
    properties: Optional[Dict[str, Any]] = None


class SARIFResult(BaseModel):
    """SARIF result."""
    ruleId: str
    level: SARIFLevel
    message: SARIFMessage
    locations: List[SARIFLocation]
    fingerprints: Optional[Dict[str, str]] = None
    codeFlows: Optional[List[SARIFCodeFlow]] = None
    properties: Optional[Dict[str, Any]] = None
    
    class Config:
        # Exclude None values from serialization
        exclude_none = True


class SARIFDriver(BaseModel):
    """SARIF driver (tool information)."""
    name: str
    version: Optional[str] = None
    semanticVersion: Optional[str] = None
    informationUri: Optional[str] = None
    rules: Optional[List[SARIFRule]] = None
    taxa: Optional[List[SARIFTaxonomy]] = None


class SARIFTool(BaseModel):
    """SARIF tool."""
    driver: SARIFDriver


class SARIFRun(BaseModel):
    """SARIF run."""
    invocations: List[SARIFInvocation]
    results: List[SARIFResult]
    tool: Optional[SARIFTool] = None


class SARIFReport(BaseModel):
    """Complete SARIF report."""
    version: str = "2.1.0"
    schema_: str = Field("https://json.schemastore.org/sarif-2.1.0.json", alias="$schema")
    runs: List[SARIFRun]


# Combined models for processing
class ProcessedFinding(BaseModel):
    """Combined V1 and V2 finding data for processing."""
    v1_finding: SemgrepV1Finding
    v2_finding: SemgrepV2Finding
    
    @property
    def has_dataflow_trace(self) -> bool:
        """Check if this finding has dataflow trace information."""
        return (
            self.v2_finding.dataflowTrace is not None
            and (
                (self.v2_finding.dataflowTrace.taintSource and len(self.v2_finding.dataflowTrace.taintSource) > 0)
                or (self.v2_finding.dataflowTrace.intermediateVars and len(self.v2_finding.dataflowTrace.intermediateVars) > 0)
                or (self.v2_finding.dataflowTrace.taintSink and len(self.v2_finding.dataflowTrace.taintSink) > 0)
            )
        )