"""Tests for data models."""

import pytest
from datetime import datetime

from src.models import (
    SemgrepV1Finding, SemgrepV1Location, SemgrepV1Rule, SemgrepV1Repository,
    SemgrepV2Finding, SemgrepV2DataflowTrace, SemgrepV2Location, SemgrepV2Position,
    ProcessedFinding, SARIFReport, SARIFRun, SARIFTool, SARIFDriver,
    SemgrepV2Severity, SemgrepV2Confidence
)


class TestSemgrepV1Models:
    """Test Semgrep V1 API models."""
    
    def test_v1_location(self):
        """Test V1 location model."""
        location_data = {
            "file_path": "src/test.py",
            "line": 10,
            "column": 5,
            "end_line": 10,
            "end_column": 15
        }
        
        location = SemgrepV1Location(**location_data)
        assert location.file_path == "src/test.py"
        assert location.line == 10
        assert location.column == 5
    
    def test_v1_rule(self):
        """Test V1 rule model."""
        rule_data = {
            "name": "test-rule",
            "message": "Test rule message",
            "category": "security",
            "confidence": "high",
            "cwe_names": ["CWE-79"],
            "owasp_names": ["A03:2021"]
        }
        
        rule = SemgrepV1Rule(**rule_data)
        assert rule.name == "test-rule"
        assert rule.cwe_names == ["CWE-79"]
    
    def test_v1_finding(self):
        """Test complete V1 finding model."""
        finding_data = {
            "id": 12345,
            "severity": "high",
            "rule_name": "test.rule",
            "rule_message": "Test finding",
            "location": {
                "file_path": "src/test.py",
                "line": 10
            },
            "rule": {
                "name": "test-rule",
                "message": "Rule message"
            }
        }
        
        finding = SemgrepV1Finding(**finding_data)
        assert finding.id == 12345
        assert finding.severity == "high"
        assert finding.location.file_path == "src/test.py"


class TestSemgrepV2Models:
    """Test Semgrep V2 API models."""
    
    def test_v2_position(self):
        """Test V2 position model."""
        position_data = {
            "line": "10",
            "col": "5", 
            "offset": "100"
        }
        
        position = SemgrepV2Position(**position_data)
        assert position.line == "10"
        assert position.col == "5"
    
    def test_v2_location(self):
        """Test V2 location model."""
        location_data = {
            "path": "src/test.py",
            "start": {"line": "10", "col": "5"},
            "end": {"line": "10", "col": "15"}
        }
        
        location = SemgrepV2Location(**location_data)
        assert location.path == "src/test.py"
        assert location.start.line == "10"
    
    def test_dataflow_trace(self):
        """Test dataflow trace model."""
        trace_data = {
            "taintSource": [
                {
                    "path": "src/input.py",
                    "start": {"line": "5", "col": "1"},
                    "end": {"line": "5", "col": "10"}
                }
            ],
            "taintSink": [
                {
                    "path": "src/output.py", 
                    "start": {"line": "20", "col": "5"},
                    "end": {"line": "20", "col": "15"}
                }
            ]
        }
        
        trace = SemgrepV2DataflowTrace(**trace_data)
        assert len(trace.taintSource) == 1
        assert len(trace.taintSink) == 1
        assert trace.taintSource[0].path == "src/input.py"
    
    def test_v2_finding_minimal(self):
        """Test V2 finding with minimal required fields."""
        finding_data = {
            "id": "test-id",
            "filePath": "src/test.py",
            "line": 10,
            "message": "Test message"
        }
        
        finding = SemgrepV2Finding(**finding_data)
        assert finding.id == "test-id"
        assert finding.filePath == "src/test.py"
        assert finding.line == 10
    
    def test_v2_finding_with_dataflow(self):
        """Test V2 finding with dataflow trace."""
        finding_data = {
            "id": "test-id",
            "filePath": "src/test.py",
            "line": 10,
            "message": "Test message",
            "dataflowTrace": {
                "taintSource": [
                    {
                        "path": "src/input.py",
                        "start": {"line": "5"},
                        "end": {"line": "5"}
                    }
                ]
            }
        }
        
        finding = SemgrepV2Finding(**finding_data)
        assert finding.dataflowTrace is not None
        assert len(finding.dataflowTrace.taintSource) == 1
    
    def test_severity_enum(self):
        """Test severity enum values."""
        assert SemgrepV2Severity.HIGH == "SEVERITY_HIGH"
        assert SemgrepV2Severity.MEDIUM == "SEVERITY_MEDIUM"
        assert SemgrepV2Severity.LOW == "SEVERITY_LOW"
    
    def test_confidence_enum(self):
        """Test confidence enum values."""
        assert SemgrepV2Confidence.HIGH == "CONFIDENCE_HIGH"
        assert SemgrepV2Confidence.MEDIUM == "CONFIDENCE_MEDIUM"
        assert SemgrepV2Confidence.LOW == "CONFIDENCE_LOW"


class TestProcessedFinding:
    """Test processed finding combination model."""
    
    def create_sample_v1_finding(self) -> SemgrepV1Finding:
        """Create a sample V1 finding for testing."""
        return SemgrepV1Finding(
            id=123,
            severity="high",
            rule_name="test.rule",
            rule_message="Test finding",
            location=SemgrepV1Location(
                file_path="src/test.py",
                line=10
            ),
            rule=SemgrepV1Rule(
                name="test-rule",
                message="Rule message"
            )
        )
    
    def create_sample_v2_finding(self, with_dataflow=False) -> SemgrepV2Finding:
        """Create a sample V2 finding for testing."""
        finding_data = {
            "id": "123",
            "filePath": "src/test.py",
            "line": 10,
            "message": "Test message"
        }
        
        if with_dataflow:
            finding_data["dataflowTrace"] = {
                "taintSource": [
                    {
                        "path": "src/input.py",
                        "start": {"line": "5"},
                        "end": {"line": "5"}
                    }
                ]
            }
        
        return SemgrepV2Finding(**finding_data)
    
    def test_processed_finding_without_dataflow(self):
        """Test processed finding without dataflow trace."""
        v1_finding = self.create_sample_v1_finding()
        v2_finding = self.create_sample_v2_finding(with_dataflow=False)
        
        processed = ProcessedFinding(
            v1_finding=v1_finding,
            v2_finding=v2_finding
        )
        
        assert not processed.has_dataflow_trace
    
    def test_processed_finding_with_dataflow(self):
        """Test processed finding with dataflow trace."""
        v1_finding = self.create_sample_v1_finding()
        v2_finding = self.create_sample_v2_finding(with_dataflow=True)
        
        processed = ProcessedFinding(
            v1_finding=v1_finding,
            v2_finding=v2_finding
        )
        
        assert processed.has_dataflow_trace


class TestSARIFModels:
    """Test SARIF output models."""
    
    def test_sarif_driver(self):
        """Test SARIF driver model."""
        driver_data = {
            "name": "Semgrep",
            "version": "1.0.0",
            "informationUri": "https://semgrep.dev"
        }
        
        driver = SARIFDriver(**driver_data)
        assert driver.name == "Semgrep"
        assert driver.version == "1.0.0"
    
    def test_sarif_report_structure(self):
        """Test complete SARIF report structure."""
        # Create minimal SARIF report
        driver = SARIFDriver(name="Semgrep")
        tool = SARIFTool(driver=driver)
        run = SARIFRun(tool=tool, results=[])
        report = SARIFReport(runs=[run])
        
        assert report.version == "2.1.0"
        assert report.schema_ == "https://json.schemastore.org/sarif-2.1.0.json"
        assert len(report.runs) == 1
        assert report.runs[0].tool.driver.name == "Semgrep"
    
    def test_sarif_report_serialization(self):
        """Test SARIF report can be serialized with aliases."""
        driver = SARIFDriver(name="Semgrep")
        tool = SARIFTool(driver=driver)
        run = SARIFRun(tool=tool, results=[])
        report = SARIFReport(runs=[run])
        
        # Test serialization with aliases
        report_dict = report.model_dump(by_alias=True)
        
        assert "$schema" in report_dict
        assert report_dict["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
        assert report_dict["version"] == "2.1.0"