"""Tests for SARIF transformation functionality."""

import pytest
from unittest.mock import Mock, patch

from src.sarif_transformer import SARIFTransformer, TransformationError
from src.models import (
    SemgrepV1Finding, SemgrepV1Location, SemgrepV1Rule,
    SemgrepV2Finding, SemgrepV2DataflowTrace, SemgrepV2Location, SemgrepV2Position,
    ProcessedFinding, SARIFLevel
)


class TestSARIFTransformer:
    """Test SARIF transformation functionality."""
    
    def create_sample_v1_finding(self, finding_id: int = 123) -> SemgrepV1Finding:
        """Create a sample V1 finding for testing."""
        return SemgrepV1Finding(
            id=finding_id,
            severity="high",
            rule_name="typescript.react.security.audit.react-no-refs.react-no-refs",
            rule_message="Test finding message",
            location=SemgrepV1Location(
                file_path="frontend/src/components/Code.tsx",
                line=120,
                column=8,
                end_line=124,
                end_column=16
            ),
            rule=SemgrepV1Rule(
                name="react-no-refs",
                message="refs give direct DOM access",
                category="security",
                confidence="high",
                cwe_names=["CWE-79: Improper Neutralization of Input"],
                owasp_names=["A03:2021 - Injection"],
                vulnerability_classes=["Cross-Site Scripting"]
            )
        )
    
    def create_sample_v2_finding(self, finding_id: str = "123", with_dataflow: bool = False) -> SemgrepV2Finding:
        """Create a sample V2 finding for testing."""
        finding_data = {
            "id": finding_id,
            "ruleId": "typescript.react.security.audit.react-no-refs.react-no-refs",
            "filePath": "frontend/src/components/Code.tsx",
            "line": 120,
            "column": 8,
            "endLine": 124,
            "endColumn": 16,
            "message": "refs give direct DOM access and may create XSS possibility",
            "severity": "SEVERITY_HIGH",
            "confidence": "CONFIDENCE_HIGH",
            "category": "security",
            "subcategories": ["vuln"],
            "ruleCweNames": ["CWE-79"],
            "ruleOwaspNames": ["A03:2021"],
            "ruleUrl": "https://semgrep.dev/r/typescript.react.security"
        }
        
        if with_dataflow:
            finding_data["dataflowTrace"] = {
                "taintSource": [
                    {
                        "path": "frontend/src/components/Input.tsx",
                        "start": {"line": "15", "col": "10", "offset": "300"},
                        "end": {"line": "15", "col": "25", "offset": "315"},
                        "locationUrl": "https://github.com/example/repo/blob/main/Input.tsx#L15"
                    }
                ],
                "intermediateVars": [
                    {
                        "path": "frontend/src/components/Utils.tsx",
                        "start": {"line": "42", "col": "5", "offset": "800"},
                        "end": {"line": "42", "col": "20", "offset": "815"}
                    }
                ],
                "taintSink": [
                    {
                        "path": "frontend/src/components/Code.tsx",
                        "start": {"line": "120", "col": "8", "offset": "2500"},
                        "end": {"line": "120", "col": "16", "offset": "2508"}
                    }
                ]
            }
        
        return SemgrepV2Finding(**finding_data)
    
    def test_severity_mapping(self):
        """Test severity mapping from Semgrep to SARIF."""
        transformer = SARIFTransformer()
        
        assert transformer._map_severity("high") == SARIFLevel.ERROR
        assert transformer._map_severity("HIGH") == SARIFLevel.ERROR
        assert transformer._map_severity("critical") == SARIFLevel.ERROR
        
        assert transformer._map_severity("medium") == SARIFLevel.WARNING
        assert transformer._map_severity("MEDIUM") == SARIFLevel.WARNING
        assert transformer._map_severity("warning") == SARIFLevel.WARNING
        
        assert transformer._map_severity("low") == SARIFLevel.NOTE
        assert transformer._map_severity("LOW") == SARIFLevel.NOTE
        assert transformer._map_severity("info") == SARIFLevel.NOTE
        
        assert transformer._map_severity("unknown") == SARIFLevel.INFO
    
    def test_combine_findings(self):
        """Test combining V1 and V2 findings by ID."""
        transformer = SARIFTransformer()
        
        v1_findings = [
            self.create_sample_v1_finding(123),
            self.create_sample_v1_finding(456)
        ]
        
        v2_findings = [
            self.create_sample_v2_finding("123"),
            self.create_sample_v2_finding("456")
        ]
        
        processed = transformer._combine_findings(v1_findings, v2_findings)
        
        assert len(processed) == 2
        assert processed[0].v1_finding.id == 123
        assert processed[0].v2_finding.id == "123"
        assert processed[1].v1_finding.id == 456
        assert processed[1].v2_finding.id == "456"
    
    def test_combine_findings_missing_v2(self):
        """Test combining when some V2 findings are missing."""
        transformer = SARIFTransformer()
        
        v1_findings = [
            self.create_sample_v1_finding(123),
            self.create_sample_v1_finding(456),
            self.create_sample_v1_finding(789)
        ]
        
        v2_findings = [
            self.create_sample_v2_finding("123"),
            self.create_sample_v2_finding("456")
            # Missing 789
        ]
        
        with patch('src.sarif_transformer.logging'):
            processed = transformer._combine_findings(v1_findings, v2_findings)
        
        assert len(processed) == 2  # Only matched findings
        assert all(p.v1_finding.id in [123, 456] for p in processed)
    
    def test_create_location(self):
        """Test creating SARIF location from finding data."""
        transformer = SARIFTransformer()
        
        v1_finding = self.create_sample_v1_finding()
        v2_finding = self.create_sample_v2_finding()
        processed_finding = ProcessedFinding(v1_finding=v1_finding, v2_finding=v2_finding)
        
        location = transformer._create_location(processed_finding)
        
        # Check artifact location
        assert location.physicalLocation.artifactLocation.uri == "frontend/src/components/Code.tsx"
        
        # Check region
        region = location.physicalLocation.region
        assert region.startLine == 120
        assert region.startColumn == 8
        assert region.endLine == 124
        assert region.endColumn == 16
    
    def test_create_properties(self):
        """Test creating properties bag from finding data."""
        transformer = SARIFTransformer()
        
        v1_finding = self.create_sample_v1_finding()
        v2_finding = self.create_sample_v2_finding()
        processed_finding = ProcessedFinding(v1_finding=v1_finding, v2_finding=v2_finding)
        
        properties = transformer._create_properties(processed_finding)
        
        assert properties["confidence"] == "CONFIDENCE_HIGH"
        assert properties["category"] == "security"
        assert properties["subcategories"] == ["vuln"]
        assert properties["vulnerability_classes"] == ["Cross-Site Scripting"]
        assert properties["rule_url"] == "https://semgrep.dev/r/typescript.react.security"
    
    def test_create_code_flows_without_dataflow(self):
        """Test creating code flows when no dataflow trace is present."""
        transformer = SARIFTransformer()
        
        v1_finding = self.create_sample_v1_finding()
        v2_finding = self.create_sample_v2_finding(with_dataflow=False)
        processed_finding = ProcessedFinding(v1_finding=v1_finding, v2_finding=v2_finding)
        
        code_flows = transformer._create_code_flows(processed_finding)
        
        assert code_flows == []
    
    def test_create_code_flows_with_dataflow(self):
        """Test creating code flows with dataflow trace."""
        transformer = SARIFTransformer()
        
        v1_finding = self.create_sample_v1_finding()
        v2_finding = self.create_sample_v2_finding(with_dataflow=True)
        processed_finding = ProcessedFinding(v1_finding=v1_finding, v2_finding=v2_finding)
        
        code_flows = transformer._create_code_flows(processed_finding)
        
        assert len(code_flows) == 1
        code_flow = code_flows[0]
        assert len(code_flow.threadFlows) == 1
        
        thread_flow = code_flow.threadFlows[0]
        locations = thread_flow.locations
        
        # Should have source + intermediate + sink = 3 locations
        assert len(locations) == 3
        
        # Check source location
        source_loc = locations[0]
        assert "source" in source_loc.kinds
        assert "taint" in source_loc.kinds
        assert source_loc.nestingLevel == 0
        assert source_loc.executionOrder == 1
        assert source_loc.importance == "essential"
        assert source_loc.location.physicalLocation.artifactLocation.uri == "frontend/src/components/Input.tsx"
        
        # Check intermediate location
        intermediate_loc = locations[1]
        assert "intermediate" in intermediate_loc.kinds
        assert intermediate_loc.nestingLevel == 1
        assert intermediate_loc.executionOrder == 2
        assert intermediate_loc.importance == "important"
        assert intermediate_loc.location.physicalLocation.artifactLocation.uri == "frontend/src/components/Utils.tsx"
        
        # Check sink location
        sink_loc = locations[2]
        assert "sink" in sink_loc.kinds
        assert sink_loc.nestingLevel == 1
        assert sink_loc.executionOrder == 3
        assert sink_loc.importance == "essential"
        assert sink_loc.location.physicalLocation.artifactLocation.uri == "frontend/src/components/Code.tsx"
    
    def test_create_rule(self):
        """Test creating SARIF rule from finding data."""
        transformer = SARIFTransformer()
        
        v1_finding = self.create_sample_v1_finding()
        v2_finding = self.create_sample_v2_finding()
        processed_finding = ProcessedFinding(v1_finding=v1_finding, v2_finding=v2_finding)
        
        rule = transformer._create_rule(processed_finding)
        
        assert rule.id == "typescript.react.security.audit.react-no-refs.react-no-refs"
        assert rule.name == "react-no-refs"
        assert rule.shortDescription.text == "refs give direct DOM access"
        assert rule.fullDescription.text == "Test finding message"
        assert rule.properties["cwe"] == ["CWE-79"]
        assert rule.properties["owasp"] == ["A03:2021"]
    
    def test_transform_finding_basic(self):
        """Test transforming a basic finding without dataflow."""
        transformer = SARIFTransformer()
        
        v1_finding = self.create_sample_v1_finding()
        v2_finding = self.create_sample_v2_finding(with_dataflow=False)
        processed_finding = ProcessedFinding(v1_finding=v1_finding, v2_finding=v2_finding)
        
        result = transformer._transform_finding(processed_finding)
        
        assert result.ruleId == "typescript.react.security.audit.react-no-refs.react-no-refs"
        assert result.level == SARIFLevel.ERROR
        assert result.message.text == "refs give direct DOM access and may create XSS possibility"
        assert len(result.locations) == 1
        assert result.codeFlows is None  # No dataflow
    
    def test_transform_finding_with_dataflow(self):
        """Test transforming a finding with dataflow trace."""
        transformer = SARIFTransformer()
        
        v1_finding = self.create_sample_v1_finding()
        v2_finding = self.create_sample_v2_finding(with_dataflow=True)
        processed_finding = ProcessedFinding(v1_finding=v1_finding, v2_finding=v2_finding)
        
        result = transformer._transform_finding(processed_finding)
        
        assert result.ruleId == "typescript.react.security.audit.react-no-refs.react-no-refs"
        assert result.level == SARIFLevel.ERROR
        assert result.codeFlows is not None
        assert len(result.codeFlows) == 1
    
    def test_transform_full_workflow(self):
        """Test the complete transformation workflow."""
        transformer = SARIFTransformer()
        
        v1_findings = [
            self.create_sample_v1_finding(123),
            self.create_sample_v1_finding(456)
        ]
        
        v2_findings = [
            self.create_sample_v2_finding("123", with_dataflow=True),
            self.create_sample_v2_finding("456", with_dataflow=False)
        ]
        
        with patch('src.sarif_transformer.logging'):
            sarif_report = transformer.transform(v1_findings, v2_findings)
        
        # Check report structure
        assert sarif_report.version == "2.1.0"
        assert len(sarif_report.runs) == 1
        
        run = sarif_report.runs[0]
        assert run.tool.driver.name == "Semgrep"
        assert len(run.results) == 2
        
        # Check first result (with dataflow)
        result1 = run.results[0]
        assert result1.codeFlows is not None
        assert len(result1.codeFlows[0].threadFlows[0].locations) == 3
        
        # Check second result (without dataflow)  
        result2 = run.results[1]
        assert result2.codeFlows is None or len(result2.codeFlows) == 0