"""Utility functions for logging and configuration."""

import json
import logging
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from pydantic import BaseModel, field_validator


class ConfigurationError(Exception):
    """Exception raised for configuration errors."""
    pass


class APICallCounter:
    """Thread-safe counter for tracking API calls with debug logging."""
    
    def __init__(self):
        self._lock = threading.Lock()
        self._v1_calls = 0
        self._v2_calls = 0
        self._debug_enabled = None
        self._logger = None
    
    def _ensure_logger(self):
        """Ensure logger is initialized and debug state is cached."""
        if self._logger is None:
            self._logger = logging.getLogger('semgrep_sarif_converter')
        if self._debug_enabled is None:
            self._debug_enabled = os.getenv('DEBUG', 'false').lower() == 'true'
    
    def increment_v1_call(self, method: str, url: str) -> int:
        """Increment V1 API call counter and log if debug is enabled."""
        self._ensure_logger()
        with self._lock:
            self._v1_calls += 1
            current_count = self._v1_calls
            
        if self._debug_enabled:
            print(f"DEBUG: V1 API Call #{current_count}: {method} {url}")
            self._logger.debug(f"V1 API Call #{current_count}: {method} {url}")
            
        return current_count
    
    def increment_v2_call(self, method: str, url: str) -> int:
        """Increment V2 API call counter and log if debug is enabled."""
        self._ensure_logger()
        with self._lock:
            self._v2_calls += 1
            current_count = self._v2_calls
            
        if self._debug_enabled:
            print(f"DEBUG: V2 API Call #{current_count}: {method} {url}")
            self._logger.debug(f"V2 API Call #{current_count}: {method} {url}")
            
        return current_count
    
    def log_response_debug(self, api_type: str, call_num: int, status_code: int, duration_ms: float):
        """Log API response details if debug is enabled."""
        self._ensure_logger()
        if self._debug_enabled:
            print(f"DEBUG: {api_type} API Call #{call_num} Response: {status_code} ({duration_ms:.1f}ms)")
            self._logger.debug(f"{api_type} API Call #{call_num} Response: {status_code} ({duration_ms:.1f}ms)")
    
    def get_counts(self) -> Dict[str, int]:
        """Get current call counts."""
        with self._lock:
            return {
                'v1_calls': self._v1_calls,
                'v2_calls': self._v2_calls,
                'total_calls': self._v1_calls + self._v2_calls
            }
    
    def log_summary(self):
        """Log summary of API calls if debug is enabled."""
        self._ensure_logger()
        if self._debug_enabled:
            counts = self.get_counts()
            print(f"DEBUG: API Call Summary - V1: {counts['v1_calls']}, V2: {counts['v2_calls']}, Total: {counts['total_calls']}")
            self._logger.debug(f"API Call Summary - V1: {counts['v1_calls']}, V2: {counts['v2_calls']}, Total: {counts['total_calls']}")


# Global API call counter instance
api_call_counter = APICallCounter()


class Config(BaseModel):
    """Configuration model for the Semgrep to SARIF converter."""
    
    api_token: str
    deployment_slug: str
    deployment_id: str
    output_sarif_path: str = "./output/results.sarif"
    filter_findings_for_specific_repo_ids: bool = False
    list_of_repo_ids: Optional[List[int]] = None
    debug_enabled: bool = False
    
    # Pagination configuration
    semgrep_page_size: int = 100  # Number of findings per API page
    semgrep_max_pages: int = 1000  # Safety limit to prevent infinite loops
    
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
    
    # Generate dynamic filename with deployment ID and datetime
    output_path = os.getenv('OUTPUT_SARIF_PATH')
    if not output_path:
        # Generate filename format: DEPLOYMENT_ID__YYYYMMDD_HHMMSS.sarif
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        if deployment_id:
            output_path = f'./output/{deployment_id}__{timestamp}.sarif'
        else:
            output_path = f'./output/results_{timestamp}.sarif'
    
    # Extract optional repository filtering variables
    filter_enabled = os.getenv('FILTER_FINDINGS_FOR_SPECIFIC_REPO_IDS', 'false').lower() == 'true'
    repo_ids_str = os.getenv('LIST_OF_REPO_IDS')
    repo_ids_list = None
    
    # Extract debug configuration
    debug_enabled = os.getenv('DEBUG', 'false').lower() == 'true'
    
    # Extract pagination configuration
    page_size = int(os.getenv('SEMGREP_PAGE_SIZE', '100'))
    max_pages = int(os.getenv('SEMGREP_MAX_PAGES', '1000'))
    
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
            list_of_repo_ids=repo_ids_list,
            debug_enabled=debug_enabled,
            semgrep_page_size=page_size,
            semgrep_max_pages=max_pages
        )
    except ValueError as e:
        raise ConfigurationError(f"Invalid configuration: {e}")


def setup_logging() -> logging.Logger:
    """Set up structured logging for the application."""
    
    # Create logs directory if it doesn't exist
    logs_dir = Path('logs')
    logs_dir.mkdir(exist_ok=True)
    
    # Check if debug mode is enabled
    debug_enabled = os.getenv('DEBUG', 'false').lower() == 'true'
    
    # Configure logging
    logger = logging.getLogger('semgrep_sarif_converter')
    logger.setLevel(logging.DEBUG if debug_enabled else logging.INFO)
    
    # Remove any existing handlers to avoid duplicates
    logger.handlers.clear()
    
    # Console handler for immediate feedback
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if debug_enabled else logging.INFO)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler for detailed logs (always DEBUG level)
    log_file = logs_dir / f"converter_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    if debug_enabled:
        logger.info("DEBUG mode enabled - detailed API call logging active")
    
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