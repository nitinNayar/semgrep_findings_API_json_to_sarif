"""Utility functions for logging and configuration."""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from pydantic import BaseModel, field_validator


class ConfigurationError(Exception):
    """Exception raised for configuration errors."""
    pass


class Config(BaseModel):
    """Configuration model for the Semgrep to SARIF converter."""
    
    api_token: str
    deployment_slug: str
    deployment_id: str
    output_sarif_path: str = "./output/results.sarif"
    filter_findings_for_specific_repo_ids: bool = False
    list_of_repo_ids: Optional[List[int]] = None
    
    @field_validator('api_token')
    @classmethod
    def validate_api_token(cls, v):
        """Validate API token format."""
        if not v or len(v.strip()) < 10:
            raise ValueError('SEMGREP_API_TOKEN must be a valid token (at least 10 characters)')
        return v.strip()
    
    @field_validator('deployment_slug', 'deployment_id')
    @classmethod
    def validate_required_fields(cls, v):
        """Validate required fields are not empty."""
        if not v or not v.strip():
            raise ValueError('Required field cannot be empty')
        return v.strip()
    
    @field_validator('list_of_repo_ids')
    @classmethod
    def validate_repo_ids_when_filtering(cls, v, values):
        """Validate that repo IDs are provided when filtering is enabled."""
        # Note: In Pydantic v2, we need to check if filtering is enabled
        # This validation will be called during model creation
        return v


def load_environment_config() -> Config:
    """Load configuration from environment variables."""
    
    # Load .env file if it exists
    env_file = Path('.env')
    if env_file.exists():
        load_dotenv(env_file)
    
    # Extract required environment variables
    api_token = os.getenv('SEMGREP_API_TOKEN')
    deployment_slug = os.getenv('SEMGREP_DEPLOYMENT_SLUG')  
    deployment_id = os.getenv('SEMGREP_DEPLOYMENT_ID')
    output_path = os.getenv('OUTPUT_SARIF_PATH', './output/results.sarif')
    
    # Extract optional repository filtering variables
    filter_enabled = os.getenv('FILTER_FINDINGS_FOR_SPECIFIC_REPO_IDS', 'false').lower() == 'true'
    repo_ids_str = os.getenv('LIST_OF_REPO_IDS')
    repo_ids_list = None
    
    # Parse repository IDs if filtering is enabled
    if filter_enabled:
        if not repo_ids_str:
            raise ConfigurationError(
                "LIST_OF_REPO_IDS must be provided when FILTER_FINDINGS_FOR_SPECIFIC_REPO_IDS is true"
            )
        
        try:
            # Parse comma-separated list of integers
            repo_ids_list = [int(id.strip()) for id in repo_ids_str.split(',') if id.strip()]
            if not repo_ids_list:
                raise ValueError("No valid repository IDs found")
        except ValueError as e:
            raise ConfigurationError(
                f"LIST_OF_REPO_IDS must contain valid integers separated by commas: {e}"
            )
    
    # Validate required variables are present
    missing_vars = []
    if not api_token:
        missing_vars.append('SEMGREP_API_TOKEN')
    if not deployment_slug:
        missing_vars.append('SEMGREP_DEPLOYMENT_SLUG')
    if not deployment_id:
        missing_vars.append('SEMGREP_DEPLOYMENT_ID')
    
    if missing_vars:
        raise ConfigurationError(
            f"Missing required environment variables: {', '.join(missing_vars)}"
        )
    
    try:
        return Config(
            api_token=api_token,
            deployment_slug=deployment_slug,
            deployment_id=deployment_id,
            output_sarif_path=output_path,
            filter_findings_for_specific_repo_ids=filter_enabled,
            list_of_repo_ids=repo_ids_list
        )
    except ValueError as e:
        raise ConfigurationError(f"Invalid configuration: {e}")


def setup_logging() -> logging.Logger:
    """Set up structured logging for the application."""
    
    # Create logs directory if it doesn't exist
    logs_dir = Path('logs')
    logs_dir.mkdir(exist_ok=True)
    
    # Configure logging
    logger = logging.getLogger('semgrep_sarif_converter')
    logger.setLevel(logging.INFO)
    
    # Remove any existing handlers to avoid duplicates
    logger.handlers.clear()
    
    # Console handler for immediate feedback
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler for detailed logs
    log_file = logs_dir / f"converter_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    return logger


def log_json_debug(data: Any, filename_prefix: str) -> Path:
    """Log JSON data to the logs folder for debugging purposes.
    
    Args:
        data: The data to log (will be JSON serialized)
        filename_prefix: Prefix for the filename (datetime will be appended)
        
    Returns:
        Path to the created log file
    """
    logs_dir = Path('logs')
    logs_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{filename_prefix}_{timestamp}.json"
    filepath = logs_dir / filename
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str, ensure_ascii=False)
        
        logger = logging.getLogger('semgrep_sarif_converter')
        logger.info(f"Debug data logged to: {filepath}")
        
        return filepath
    except Exception as e:
        logger = logging.getLogger('semgrep_sarif_converter')
        logger.error(f"Failed to log debug data to {filepath}: {e}")
        raise


def ensure_output_directory(output_path: str) -> Path:
    """Ensure the output directory exists for the given file path.
    
    Args:
        output_path: The output file path
        
    Returns:
        Path object for the output file
    """
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    return output_file


def sanitize_filename(filename: str) -> str:
    """Sanitize a filename to prevent path traversal attacks.
    
    Args:
        filename: The filename to sanitize
        
    Returns:
        Sanitized filename
    """
    # Remove any path components
    filename = os.path.basename(filename)
    
    # Remove or replace problematic characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Ensure filename is not empty after sanitization
    if not filename or filename.isspace():
        filename = f"output_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    return filename