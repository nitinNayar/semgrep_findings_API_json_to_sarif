"""Tests for utility functions."""

import os
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, mock_open

from src.utils import (
    Config, ConfigurationError, load_environment_config,
    log_json_debug, sanitize_filename, ensure_output_directory
)


class TestConfig:
    """Test Config model validation."""
    
    def test_valid_config(self):
        """Test valid configuration."""
        config = Config(
            api_token="sg_test_token",
            deployment_slug="test-slug", 
            deployment_id="test-id"
        )
        assert config.api_token == "sg_test_token"
        assert config.deployment_slug == "test-slug"
        assert config.deployment_id == "test-id"
        assert config.output_sarif_path == "./output/results.sarif"
        assert config.filter_findings_for_specific_repo_ids == False
        assert config.list_of_repo_ids is None
    
    def test_config_with_repository_filtering(self):
        """Test configuration with repository filtering enabled."""
        config = Config(
            api_token="sg_test_token",
            deployment_slug="test-slug",
            deployment_id="test-id",
            filter_findings_for_specific_repo_ids=True,
            list_of_repo_ids=[1, 2, 3]
        )
        assert config.filter_findings_for_specific_repo_ids == True
        assert config.list_of_repo_ids == [1, 2, 3]
    
    def test_invalid_api_token(self):
        """Test API token validation."""
        with pytest.raises(ValueError, match='must be a valid token'):
            Config(
                api_token="short",
                deployment_slug="test-slug",
                deployment_id="test-id"
            )
    
    def test_empty_deployment_slug(self):
        """Test empty deployment slug validation."""
        with pytest.raises(ValueError, match="Required field cannot be empty"):
            Config(
                api_token="sg_test_token",
                deployment_slug="",
                deployment_id="test-id"
            )
    
    def test_whitespace_fields(self):
        """Test whitespace handling in required fields."""
        config = Config(
            api_token="sg_test_token",
            deployment_slug="  test-slug  ",
            deployment_id="  test-id  "
        )
        assert config.deployment_slug == "test-slug"
        assert config.deployment_id == "test-id"


class TestLoadEnvironmentConfig:
    """Test environment configuration loading."""
    
    def test_load_valid_config(self):
        """Test loading valid configuration from environment."""
        env_vars = {
            'SEMGREP_API_TOKEN': 'sg_test_token',
            'SEMGREP_DEPLOYMENT_SLUG': 'test-slug',
            'SEMGREP_DEPLOYMENT_ID': 'test-id',
            'OUTPUT_SARIF_PATH': './custom/output.sarif'
        }
        
        with patch.dict(os.environ, env_vars, clear=True), patch('src.utils.Path.exists', return_value=False):
            config = load_environment_config()
            
        assert config.api_token == 'sg_test_token'
        assert config.deployment_slug == 'test-slug'
        assert config.deployment_id == 'test-id'
        assert config.output_sarif_path == './custom/output.sarif'
    
    def test_missing_required_vars(self):
        """Test error when required environment variables are missing."""
        with patch.dict(os.environ, {}, clear=True), patch('src.utils.Path.exists', return_value=False):
            with pytest.raises(ConfigurationError, match="Missing required environment variables"):
                load_environment_config()
    
    def test_partial_missing_vars(self):
        """Test error when some required variables are missing."""
        env_vars = {
            'SEMGREP_API_TOKEN': 'sg_test_token',
            # Missing SEMGREP_DEPLOYMENT_SLUG and SEMGREP_DEPLOYMENT_ID
        }
        
        with patch.dict(os.environ, env_vars, clear=True), patch('src.utils.Path.exists', return_value=False):
            with pytest.raises(ConfigurationError, match="SEMGREP_DEPLOYMENT_SLUG"):
                load_environment_config()
    
    def test_default_output_path(self):
        """Test default output path when not specified."""
        env_vars = {
            'SEMGREP_API_TOKEN': 'sg_test_token',
            'SEMGREP_DEPLOYMENT_SLUG': 'test-slug',
            'SEMGREP_DEPLOYMENT_ID': 'test-id'
        }
        
        with patch.dict(os.environ, env_vars, clear=True), patch('src.utils.Path.exists', return_value=False):
            config = load_environment_config()
            
        assert config.output_sarif_path == './output/results.sarif'
        assert config.filter_findings_for_specific_repo_ids == False
        assert config.list_of_repo_ids is None
    
    def test_repository_filtering_enabled(self):
        """Test repository filtering configuration."""
        env_vars = {
            'SEMGREP_API_TOKEN': 'sg_test_token',
            'SEMGREP_DEPLOYMENT_SLUG': 'test-slug',
            'SEMGREP_DEPLOYMENT_ID': 'test-id',
            'FILTER_FINDINGS_FOR_SPECIFIC_REPO_IDS': 'true',
            'LIST_OF_REPO_IDS': '1,2,3'
        }
        
        with patch.dict(os.environ, env_vars, clear=True), patch('src.utils.Path.exists', return_value=False):
            config = load_environment_config()
            
        assert config.filter_findings_for_specific_repo_ids == True
        assert config.list_of_repo_ids == [1, 2, 3]
    
    def test_repository_filtering_with_whitespace(self):
        """Test repository ID parsing with whitespace."""
        env_vars = {
            'SEMGREP_API_TOKEN': 'sg_test_token',
            'SEMGREP_DEPLOYMENT_SLUG': 'test-slug',
            'SEMGREP_DEPLOYMENT_ID': 'test-id',
            'FILTER_FINDINGS_FOR_SPECIFIC_REPO_IDS': 'true',
            'LIST_OF_REPO_IDS': ' 1 , 2 , 3 '
        }
        
        with patch.dict(os.environ, env_vars, clear=True), patch('src.utils.Path.exists', return_value=False):
            config = load_environment_config()
            
        assert config.list_of_repo_ids == [1, 2, 3]
    
    def test_repository_filtering_missing_repo_ids(self):
        """Test error when filtering enabled but no repo IDs provided."""
        env_vars = {
            'SEMGREP_API_TOKEN': 'sg_test_token',
            'SEMGREP_DEPLOYMENT_SLUG': 'test-slug',
            'SEMGREP_DEPLOYMENT_ID': 'test-id',
            'FILTER_FINDINGS_FOR_SPECIFIC_REPO_IDS': 'true'
            # Missing LIST_OF_REPO_IDS
        }
        
        with patch.dict(os.environ, env_vars, clear=True), patch('src.utils.Path.exists', return_value=False):
            with pytest.raises(ConfigurationError, match="LIST_OF_REPO_IDS must be provided"):
                load_environment_config()
    
    def test_repository_filtering_invalid_repo_ids(self):
        """Test error when repo IDs contain invalid values."""
        env_vars = {
            'SEMGREP_API_TOKEN': 'sg_test_token',
            'SEMGREP_DEPLOYMENT_SLUG': 'test-slug',
            'SEMGREP_DEPLOYMENT_ID': 'test-id',
            'FILTER_FINDINGS_FOR_SPECIFIC_REPO_IDS': 'true',
            'LIST_OF_REPO_IDS': '1,abc,3'
        }
        
        with patch.dict(os.environ, env_vars, clear=True), patch('src.utils.Path.exists', return_value=False):
            with pytest.raises(ConfigurationError, match="must contain valid integers"):
                load_environment_config()
    
    def test_repository_filtering_empty_repo_ids(self):
        """Test error when repo IDs list is empty."""
        env_vars = {
            'SEMGREP_API_TOKEN': 'sg_test_token',
            'SEMGREP_DEPLOYMENT_SLUG': 'test-slug',
            'SEMGREP_DEPLOYMENT_ID': 'test-id',
            'FILTER_FINDINGS_FOR_SPECIFIC_REPO_IDS': 'true',
            'LIST_OF_REPO_IDS': '  ,  ,  '
        }
        
        with patch.dict(os.environ, env_vars, clear=True), patch('src.utils.Path.exists', return_value=False):
            with pytest.raises(ConfigurationError, match="No valid repository IDs found"):
                load_environment_config()


class TestLogJsonDebug:
    """Test JSON debug logging functionality."""
    
    def test_log_json_debug(self):
        """Test logging JSON data to debug file."""
        test_data = {"test": "data", "number": 123}
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Change to temp directory
            original_cwd = os.getcwd()
            os.chdir(temp_dir)
            
            try:
                filepath = log_json_debug(test_data, "test_prefix")
                
                # Check file was created
                assert filepath.exists()
                assert filepath.name.startswith("test_prefix_")
                assert filepath.suffix == ".json"
                
                # Check content
                import json
                with open(filepath) as f:
                    loaded_data = json.load(f)
                assert loaded_data == test_data
                
            finally:
                os.chdir(original_cwd)


class TestSanitizeFilename:
    """Test filename sanitization."""
    
    def test_basic_filename(self):
        """Test basic filename passes through."""
        result = sanitize_filename("test.sarif")
        assert result == "test.sarif"
    
    def test_path_components_removed(self):
        """Test path components are removed."""
        result = sanitize_filename("/path/to/file.sarif")
        assert result == "file.sarif"
        
        result = sanitize_filename("../../../etc/passwd")
        assert result == "passwd"
    
    def test_invalid_characters_replaced(self):
        """Test invalid characters are replaced."""
        result = sanitize_filename('file<>:"/\\|?*.sarif')
        # os.path.basename treats some chars as path separators, so we get "*.sarif" -> "____.sarif"
        assert result == "____.sarif"
    
    def test_empty_filename_fallback(self):
        """Test fallback for empty filename after sanitization."""
        result = sanitize_filename("")
        assert result.startswith("output_")
        
        result = sanitize_filename("   ")
        assert result.startswith("output_")


class TestEnsureOutputDirectory:
    """Test output directory creation."""
    
    def test_ensure_output_directory(self):
        """Test output directory is created."""
        with tempfile.TemporaryDirectory() as temp_dir:
            test_path = Path(temp_dir) / "subdir" / "output.sarif"
            
            result = ensure_output_directory(str(test_path))
            
            assert result == test_path
            assert test_path.parent.exists()
            assert test_path.parent.is_dir()
    
    def test_existing_directory(self):
        """Test handling of existing directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            test_path = Path(temp_dir) / "output.sarif"
            
            result = ensure_output_directory(str(test_path))
            
            assert result == test_path
            assert test_path.parent.exists()