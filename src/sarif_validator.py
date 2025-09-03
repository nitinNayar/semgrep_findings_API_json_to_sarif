"""SARIF validation and output handling."""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

import jsonschema
from jsonschema.exceptions import ValidationError
import requests

from .models import SARIFReport
from .utils import ensure_output_directory, sanitize_filename


class SARIFValidationError(Exception):
    """Exception raised when SARIF validation fails."""
    pass


class SARIFOutputError(Exception):
    """Exception raised when SARIF output fails."""
    pass


class SARIFValidator:
    """Validates SARIF reports against the 2.1.0 schema."""
    
    SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"
    
    def __init__(self):
        """Initialize the SARIF validator."""
        self.logger = logging.getLogger(__name__)
        self._schema = None
    
    def _get_schema(self) -> Dict[str, Any]:
        """Get the SARIF 2.1.0 schema, downloading if necessary.
        
        Returns:
            SARIF schema dictionary
        """
        if self._schema is None:
            try:
                self.logger.info("Downloading SARIF 2.1.0 schema")
                response = requests.get(self.SARIF_SCHEMA_URL, timeout=30)
                response.raise_for_status()
                self._schema = response.json()
                self.logger.debug("SARIF schema downloaded successfully")
            except Exception as e:
                self.logger.error(f"Failed to download SARIF schema: {e}")
                # Fall back to basic structure validation
                self._schema = self._get_basic_schema()
        
        return self._schema
    
    def _get_basic_schema(self) -> Dict[str, Any]:
        """Get a basic SARIF schema for fallback validation.
        
        Returns:
            Basic SARIF schema
        """
        return {
            "type": "object",
            "required": ["version", "$schema", "runs"],
            "properties": {
                "version": {"const": "2.1.0"},
                "$schema": {"type": "string"},
                "runs": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["invocations", "results"],
                        "properties": {
                            "invocations": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["executionSuccessful"],
                                    "properties": {
                                        "executionSuccessful": {"type": "boolean"},
                                        "toolExecutionNotifications": {
                                            "type": "array",
                                            "items": {"type": "object"}
                                        }
                                    }
                                }
                            },
                            "results": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["ruleId", "level", "message", "locations"],
                                    "properties": {
                                        "ruleId": {"type": "string"},
                                        "level": {
                                            "enum": ["error", "warning", "note", "info"]
                                        },
                                        "message": {
                                            "type": "object",
                                            "required": ["text"],
                                            "properties": {
                                                "text": {"type": "string"}
                                            }
                                        },
                                        "locations": {"type": "array"}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    
    def validate(self, sarif_report: SARIFReport) -> bool:
        """Validate a SARIF report against the schema.
        
        Args:
            sarif_report: SARIF report to validate
            
        Returns:
            True if valid
            
        Raises:
            SARIFValidationError: If validation fails
        """
        try:
            # Convert to dictionary, excluding None values
            sarif_dict = sarif_report.model_dump(by_alias=True, exclude_none=True)
            
            # Get schema
            schema = self._get_schema()
            
            # Validate
            jsonschema.validate(sarif_dict, schema)
            
            self.logger.info("SARIF report validation successful")
            return True
            
        except ValidationError as e:
            error_msg = f"SARIF validation failed: {e.message}"
            if e.absolute_path:
                error_msg += f" at path: {'.'.join(str(p) for p in e.absolute_path)}"
            self.logger.error(error_msg)
            raise SARIFValidationError(error_msg)
        except Exception as e:
            error_msg = f"SARIF validation error: {e}"
            self.logger.error(error_msg)
            raise SARIFValidationError(error_msg)


class SARIFOutputHandler:
    """Handles SARIF report output to files."""
    
    def __init__(self, validate_output: bool = True):
        """Initialize the output handler.
        
        Args:
            validate_output: Whether to validate SARIF before output
        """
        self.logger = logging.getLogger(__name__)
        self.validator = SARIFValidator() if validate_output else None
    
    def write_sarif_file(self, sarif_report: SARIFReport, output_path: str) -> Path:
        """Write SARIF report to a file.
        
        Args:
            sarif_report: SARIF report to write
            output_path: Output file path
            
        Returns:
            Path to the written file
            
        Raises:
            SARIFOutputError: If file writing fails
            SARIFValidationError: If validation fails (when enabled)
        """
        try:
            # Validate if validator is configured
            if self.validator:
                self.validator.validate(sarif_report)
            
            # Ensure output directory exists and sanitize filename
            output_file = ensure_output_directory(output_path)
            
            # Convert to JSON with proper formatting, excluding None values
            sarif_dict = sarif_report.model_dump(by_alias=True, exclude_none=True)
            
            # Write to file
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(sarif_dict, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"SARIF report written to: {output_file}")
            if sarif_report.runs:
                self.logger.info(f"Report contains {len(sarif_report.runs[0].results)} results")
            
            return output_file
            
        except (SARIFValidationError, SARIFOutputError):
            # Re-raise validation and output errors as-is
            raise
        except Exception as e:
            error_msg = f"Failed to write SARIF file to {output_path}: {e}"
            self.logger.error(error_msg)
            raise SARIFOutputError(error_msg)
    
    def get_sarif_summary(self, sarif_report: SARIFReport) -> Dict[str, Any]:
        """Get a summary of the SARIF report contents.
        
        Args:
            sarif_report: SARIF report to summarize
            
        Returns:
            Dictionary containing report summary
        """
        if not sarif_report.runs:
            return {"error": "No runs found in SARIF report"}
        
        run = sarif_report.runs[0]
        results = run.results
        
        # Count results by level
        level_counts = {}
        rule_counts = {}
        files_with_issues = set()
        
        for result in results:
            # Count by level
            level = result.level.value
            level_counts[level] = level_counts.get(level, 0) + 1
            
            # Count by rule
            rule_id = result.ruleId
            rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
            
            # Track files with issues
            for location in result.locations:
                file_path = location.physicalLocation.artifactLocation.uri
                files_with_issues.add(file_path)
        
        # Count results with dataflow traces
        dataflow_count = sum(1 for result in results if result.codeFlows)
        
        summary = {
            "version": sarif_report.version,
            "total_results": len(results),
            "results_by_level": level_counts,
            "unique_rules": len(rule_counts),
            "files_with_issues": len(files_with_issues),
            "results_with_dataflow": dataflow_count,
            "invocations_successful": len([inv for inv in run.invocations if inv.executionSuccessful])
        }
        
        return summary
    
    def validate_and_write(self, sarif_report: SARIFReport, output_path: str) -> tuple[Path, Dict[str, Any]]:
        """Validate and write SARIF report, returning both file path and summary.
        
        Args:
            sarif_report: SARIF report to process
            output_path: Output file path
            
        Returns:
            Tuple of (output file path, report summary)
        """
        # Write the file
        output_file = self.write_sarif_file(sarif_report, output_path)
        
        # Get summary
        summary = self.get_sarif_summary(sarif_report)
        
        return output_file, summary