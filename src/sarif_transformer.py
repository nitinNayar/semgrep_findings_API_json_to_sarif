"""SARIF transformation engine for converting Semgrep findings to SARIF format."""

import logging
from typing import List, Dict, Any, Optional, Set
from pathlib import Path
from urllib.parse import urlparse

from .models import (
    SemgrepV1Finding, SemgrepV2Finding, ProcessedFinding,
    SemgrepV2Severity, SemgrepV2Confidence,
    SARIFReport, SARIFRun, SARIFResult, SARIFLevel,
    SARIFLocation, SARIFPhysicalLocation, SARIFArtifactLocation, SARIFRegion,
    SARIFMessage, SARIFCodeFlow, SARIFThreadFlow, SARIFThreadFlowLocation,
    SARIFInvocation, SARIFToolExecutionNotification, SARIFTool, SARIFDriver, SARIFRule
)


class TransformationError(Exception):
    """Exception raised during SARIF transformation."""
    pass


class SARIFTransformer:
    """Transforms Semgrep findings to SARIF 2.1.0 format."""
    
    def __init__(self, include_tool_section: bool = True):
        """Initialize the SARIF transformer.
        
        Args:
            include_tool_section: Whether to include tool section for GitHub compatibility
        """
        self.logger = logging.getLogger(__name__)
        self.include_tool_section = include_tool_section
    
    def transform(
        self, 
        v1_findings: List[SemgrepV1Finding], 
        v2_findings: List[SemgrepV2Finding]
    ) -> SARIFReport:
        """Transform Semgrep findings to SARIF format.
        
        Args:
            v1_findings: List of V1 API findings
            v2_findings: List of V2 API findings
            
        Returns:
            Complete SARIF report
        """
        self.logger.info("Starting SARIF transformation")
        
        # Combine V1 and V2 findings
        processed_findings = self._combine_findings(v1_findings, v2_findings)
        
        # Transform to SARIF results
        sarif_results = []
        
        for finding in processed_findings:
            try:
                result = self._transform_finding(finding)
                sarif_results.append(result)
                
            except Exception as e:
                self.logger.warning(f"Failed to transform finding {finding.v1_finding.id}: {e}")
                continue
        
        # Create invocations array instead of tool section
        invocations = self._create_invocations(v1_findings, v2_findings)
        
        # Create tool section if enabled
        tool_section = self._create_tool_section(processed_findings)
        
        # Create SARIF run
        run = SARIFRun(
            invocations=invocations,
            results=sarif_results,
            tool=tool_section
        )
        
        # Create final SARIF report
        report = SARIFReport(runs=[run])
        
        self.logger.info(f"SARIF transformation complete: {len(sarif_results)} results")
        
        return report
    
    def _combine_findings(
        self, 
        v1_findings: List[SemgrepV1Finding], 
        v2_findings: List[SemgrepV2Finding]
    ) -> List[ProcessedFinding]:
        """Combine V1 and V2 findings by matching IDs.
        
        Args:
            v1_findings: List of V1 findings
            v2_findings: List of V2 findings
            
        Returns:
            List of combined processed findings
        """
        # Create lookup dictionary for V2 findings by ID
        v2_lookup = {finding.id: finding for finding in v2_findings}
        
        processed_findings = []
        
        for v1_finding in v1_findings:
            v1_id = str(v1_finding.id)
            
            if v1_id in v2_lookup:
                processed_finding = ProcessedFinding(
                    v1_finding=v1_finding,
                    v2_finding=v2_lookup[v1_id]
                )
                processed_findings.append(processed_finding)
            else:
                self.logger.warning(f"No V2 details found for V1 finding ID: {v1_id}")
        
        self.logger.info(f"Combined {len(processed_findings)} findings with V1+V2 data")
        
        return processed_findings
    
    
    
    
    def _transform_finding(self, finding: ProcessedFinding) -> SARIFResult:
        """Transform a single finding to SARIF result.
        
        Args:
            finding: Combined V1+V2 finding data
            
        Returns:
            SARIF result
        """
        # Map severity
        level = self._map_severity(finding.v1_finding.severity)
        
        # Create message
        message = SARIFMessage(text=finding.v2_finding.message)
        
        # Create primary location
        primary_location = self._create_location(finding)
        
        # Use Semgrep's existing ID as fingerprint
        fingerprints = {"matchBasedId/v1": str(finding.v1_finding.id) + "_0"}
        
        # Create base result
        result = SARIFResult(
            ruleId=finding.v1_finding.rule_name,
            level=level,
            message=message,
            locations=[primary_location],
            fingerprints=fingerprints,
            properties=self._create_properties(finding)
        )
        
        # Add dataflow information if available
        if finding.has_dataflow_trace:
            code_flows = self._create_code_flows(finding)
            if code_flows:
                result.codeFlows = code_flows
        
        return result
    
    def _create_location(self, finding: ProcessedFinding) -> SARIFLocation:
        """Create SARIF location from finding data.
        
        Args:
            finding: Combined finding data
            
        Returns:
            SARIF location with enhancements (uriBaseId, snippet)
        """
        # Use V2 data preferentially, fall back to V1
        file_path = finding.v2_finding.filePath or finding.v1_finding.location.file_path
        start_line = finding.v2_finding.line or finding.v1_finding.location.line
        start_column = finding.v2_finding.column or finding.v1_finding.location.column
        end_line = finding.v2_finding.endLine or finding.v1_finding.location.end_line
        end_column = finding.v2_finding.endColumn or finding.v1_finding.location.end_column
        
        # Normalize file path (remove leading slashes, use forward slashes)
        normalized_path = file_path.lstrip('/').replace('\\', '/')
        
        # Create artifact location with uriBaseId
        artifact_location = SARIFArtifactLocation(
            uri=normalized_path,
            uriBaseId="%SRCROOT%"
        )
        
        # Create region with property reordering (endColumn/endLine before startColumn/startLine)
        region = SARIFRegion(
            endColumn=end_column,
            endLine=end_line,
            startColumn=start_column,
            startLine=start_line
        )
        
        # Create physical location
        physical_location = SARIFPhysicalLocation(
            artifactLocation=artifact_location,
            region=region
        )
        
        return SARIFLocation(physicalLocation=physical_location)
    
    def _create_properties(self, finding: ProcessedFinding) -> Dict[str, Any]:
        """Create properties bag for SARIF result.
        
        Based on expected SARIF format, properties should be empty.
        
        Args:
            finding: Combined finding data
            
        Returns:
            Empty properties dictionary
        """
        return {}
    
    def _create_code_flows(self, finding: ProcessedFinding) -> List[SARIFCodeFlow]:
        """Create SARIF code flows from dataflow trace with descriptive messages.
        
        Args:
            finding: Combined finding data with dataflow trace
            
        Returns:
            List of SARIF code flows
        """
        if not finding.has_dataflow_trace:
            return []
        
        trace = finding.v2_finding.dataflowTrace
        thread_flow_locations = []
        
        # Collect source and sink file info for the flow message
        source_file = None
        source_line = None
        sink_file = None
        sink_line = None
        
        # Process taint sources
        if trace.taintSource:
            for source in trace.taintSource:
                location = self._create_dataflow_location(source, "Source")
                thread_flow_location = SARIFThreadFlowLocation(
                    location=location,
                    nestingLevel=0
                    # Remove executionOrder and importance
                )
                thread_flow_locations.append(thread_flow_location)
                
                # Capture first source info for flow message
                if source_file is None:
                    source_file = source.path
                    source_line = int(source.start.line) if source.start.line else 1
        
        # Process intermediate variables
        if trace.intermediateVars:
            for intermediate in trace.intermediateVars:
                location = self._create_dataflow_location(intermediate, "Propagator")
                thread_flow_location = SARIFThreadFlowLocation(
                    location=location,
                    nestingLevel=0
                    # Remove executionOrder and importance
                )
                thread_flow_locations.append(thread_flow_location)
        
        # Process taint sinks  
        if trace.taintSink:
            for sink in trace.taintSink:
                location = self._create_dataflow_location(sink, "Sink")
                thread_flow_location = SARIFThreadFlowLocation(
                    location=location,
                    nestingLevel=1
                    # Remove executionOrder and importance
                )
                thread_flow_locations.append(thread_flow_location)
                
                # Capture last sink info for flow message
                sink_file = sink.path
                sink_line = int(sink.start.line) if sink.start.line else 1
        
        if not thread_flow_locations:
            return []
        
        # Create descriptive flow message
        if source_file and sink_file:
            flow_message = f"Untrusted dataflow from {source_file}:{source_line} to {sink_file}:{sink_line}"
        else:
            flow_message = "Tainted data flow"
        
        # Create thread flow
        thread_flow = SARIFThreadFlow(
            locations=thread_flow_locations
        )
        
        # Create code flow with descriptive message
        code_flow = SARIFCodeFlow(
            threadFlows=[thread_flow],
            message=SARIFMessage(text=flow_message)
        )
        
        return [code_flow]
    
    def _create_dataflow_location(self, dataflow_location, step_type: str, variable_name: str = None) -> SARIFLocation:
        """Create SARIF location from dataflow trace location with descriptive message.
        
        Args:
            dataflow_location: Semgrep V2 dataflow location
            step_type: Type of step ("Source", "Propagator", "Sink")
            variable_name: Optional variable name for the step
            
        Returns:
            SARIF location with descriptive message
        """
        # Normalize file path
        file_path = dataflow_location.path.lstrip('/').replace('\\', '/')
        
        # Create artifact location with uriBaseId
        artifact_location = SARIFArtifactLocation(
            uri=file_path,
            uriBaseId="%SRCROOT%"
        )
        
        # Create region from start/end positions
        start_line = int(dataflow_location.start.line) if dataflow_location.start.line else 1
        start_col = int(dataflow_location.start.col) if dataflow_location.start.col else None
        end_line = int(dataflow_location.end.line) if dataflow_location.end.line else None
        end_col = int(dataflow_location.end.col) if dataflow_location.end.col else None
        
        # Create descriptive message
        if variable_name:
            message_text = f"{step_type}: '{variable_name}' @ '{file_path}:{start_line}'"
        else:
            message_text = f"{step_type} @ '{file_path}:{start_line}'"
        
        region = SARIFRegion(
            endColumn=end_col,
            endLine=end_line,
            startColumn=start_col,
            startLine=start_line
        )
        
        # Create physical location
        physical_location = SARIFPhysicalLocation(
            artifactLocation=artifact_location,
            region=region
        )
        
        return SARIFLocation(
            physicalLocation=physical_location,
            message={"text": message_text}
        )
    
    
    def _create_invocations(
        self, 
        v1_findings: List[SemgrepV1Finding], 
        v2_findings: List[SemgrepV2Finding]
    ) -> List[SARIFInvocation]:
        """Create SARIF invocations with tool execution notifications.
        
        Args:
            v1_findings: V1 findings (for extracting any tool errors)
            v2_findings: V2 findings (for extracting any tool errors)
            
        Returns:
            List of SARIF invocations
        """
        notifications = []
        
        # For now, we'll create a simple successful invocation
        # In the future, we could extract actual Semgrep error messages
        # and convert them to toolExecutionNotifications
        
        invocation = SARIFInvocation(
            executionSuccessful=True,
            toolExecutionNotifications=notifications if notifications else None
        )
        
        return [invocation]
    
    def _map_severity(self, severity: str) -> SARIFLevel:
        """Map Semgrep severity to SARIF level.
        
        Args:
            severity: Semgrep severity string
            
        Returns:
            SARIF level enum
        """
        severity_lower = severity.lower()
        
        if severity_lower in ['high', 'error', 'critical', 'severity_critical', 'severity_high']:
            return SARIFLevel.ERROR
        elif severity_lower in ['medium', 'warning', 'warn', 'severity_medium']:
            return SARIFLevel.WARNING
        elif severity_lower in ['low', 'note', 'info', 'severity_low', 'severity_info']:
            return SARIFLevel.NOTE
        else:
            # Default to info for unknown severities
            return SARIFLevel.INFO
    
    def _create_tool_section(self, processed_findings: List[ProcessedFinding]) -> Optional[SARIFTool]:
        """Create tool section with rule definitions for GitHub compatibility.
        
        Args:
            processed_findings: List of processed findings to extract rules from
            
        Returns:
            SARIF tool section or None if disabled
        """
        if not self.include_tool_section:
            return None
        
        # Extract unique rules from findings
        unique_rules = self._extract_unique_rules(processed_findings)
        
        # Create driver with rules
        driver = SARIFDriver(
            name="Semgrep PRO",
            semanticVersion="1.131.0",
            informationUri="https://semgrep.dev",
            rules=unique_rules
        )
        
        return SARIFTool(driver=driver)
    
    def _extract_unique_rules(self, processed_findings: List[ProcessedFinding]) -> List[SARIFRule]:
        """Extract unique rule definitions from processed findings.
        
        Args:
            processed_findings: List of processed findings
            
        Returns:
            List of unique SARIF rule definitions
        """
        rules_dict = {}
        
        for finding in processed_findings:
            # Use V1 rule name (fully qualified) instead of V2 numeric ruleId
            rule_id = finding.v1_finding.rule_name
            
            if rule_id not in rules_dict:
                # Use V2 finding for richer description if available
                v2_finding = finding.v2_finding
                description = v2_finding.message if v2_finding and v2_finding.message else finding.v1_finding.rule.message
                
                # Create rule definition
                rule = SARIFRule(
                    id=rule_id,
                    shortDescription=SARIFMessage(text=f"Semgrep Finding: {rule_id}"),
                    fullDescription=SARIFMessage(text=description),
                    defaultConfiguration={"level": self._map_severity(finding.v1_finding.severity).value},
                    properties={
                        "precision": "high",
                        "tags": ["security"]
                    }
                )
                
                # Add help URI based on rule name (Semgrep pattern)
                if rule_id and rule_id.count('.') >= 2:  # Check if it's a semgrep rule format
                    rule.helpUri = f"https://semgrep.dev/r/{rule_id}"
                
                rules_dict[rule_id] = rule
        
        return list(rules_dict.values())