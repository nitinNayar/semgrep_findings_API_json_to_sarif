"""Tests for repository filtering functionality."""

import pytest
from unittest.mock import Mock, patch
from src.semgrep_client import SemgrepV1Client, SemgrepAPIFacade
from src.models import SemgrepV1Response, SemgrepV1Finding, SemgrepV1Location, SemgrepV1Rule


class TestSemgrepV1ClientRepositoryFiltering:
    """Test repository filtering in V1 client."""
    
    def test_get_findings_without_repository_filter(self):
        """Test getting findings without repository filtering."""
        client = SemgrepV1Client("test_token")
        
        # Mock the HTTP request
        mock_response = {
            "findings": []
        }
        
        with patch.object(client, '_make_request', return_value=mock_response) as mock_request:
            findings = client.get_findings("test-deployment")
            
            # Verify no query parameters were added
            mock_request.assert_called_once_with("GET", 
                "https://semgrep.dev/api/v1/deployments/test-deployment/findings",
                params={}
            )
            assert findings == []
    
    def test_get_findings_with_repository_filter(self):
        """Test getting findings with repository filtering."""
        client = SemgrepV1Client("test_token")
        
        # Mock the HTTP request
        mock_response = {
            "findings": []
        }
        
        with patch.object(client, '_make_request', return_value=mock_response) as mock_request:
            findings = client.get_findings("test-deployment", repository_ids=[1, 2, 3])
            
            # Verify query parameters were added correctly
            mock_request.assert_called_once_with("GET", 
                "https://semgrep.dev/api/v1/deployments/test-deployment/findings",
                params={'repository_ids': '1,2,3'}
            )
            assert findings == []
    
    def test_get_findings_with_single_repository(self):
        """Test getting findings with single repository ID."""
        client = SemgrepV1Client("test_token")
        
        mock_response = {
            "findings": []
        }
        
        with patch.object(client, '_make_request', return_value=mock_response) as mock_request:
            findings = client.get_findings("test-deployment", repository_ids=[42])
            
            # Verify single ID is formatted correctly
            mock_request.assert_called_once_with("GET", 
                "https://semgrep.dev/api/v1/deployments/test-deployment/findings",
                params={'repository_ids': '42'}
            )
            assert findings == []


class TestSemgrepAPIFacadeRepositoryFiltering:
    """Test repository filtering in API facade."""
    
    def test_facade_without_repository_filtering(self):
        """Test facade initialization without repository filtering."""
        facade = SemgrepAPIFacade(
            api_token="test_token",
            deployment_slug="test-slug",
            deployment_id="test-id"
        )
        
        assert facade.repository_ids is None
    
    def test_facade_with_repository_filtering(self):
        """Test facade initialization with repository filtering."""
        facade = SemgrepAPIFacade(
            api_token="test_token",
            deployment_slug="test-slug",
            deployment_id="test-id",
            repository_ids=[1, 2, 3]
        )
        
        assert facade.repository_ids == [1, 2, 3]
    
    def test_fetch_all_findings_passes_repository_ids(self):
        """Test that repository IDs are passed to V1 client."""
        facade = SemgrepAPIFacade(
            api_token="test_token",
            deployment_slug="test-slug",
            deployment_id="test-id",
            repository_ids=[1, 2]
        )
        
        # Mock the V1 and V2 clients
        mock_v1_findings = []
        mock_v2_findings = []
        
        with patch.object(facade.v1_client, 'get_findings', return_value=mock_v1_findings) as mock_v1, \
             patch.object(facade.v2_client, 'get_all_finding_details', return_value=mock_v2_findings) as mock_v2, \
             patch('src.semgrep_client.log_json_debug'):
            
            v1_findings, v2_findings = facade.fetch_all_findings_with_details()
            
            # Verify V1 client was called with repository IDs
            mock_v1.assert_called_once_with("test-slug", [1, 2])
            
            # V2 should be called with empty list since V1 returned no findings
            mock_v2.assert_called_once_with("test-id", [])
            
            assert v1_findings == []
            assert v2_findings == []
    
    def test_fetch_all_findings_without_repository_ids(self):
        """Test that None repository IDs work correctly."""
        facade = SemgrepAPIFacade(
            api_token="test_token",
            deployment_slug="test-slug",
            deployment_id="test-id",
            repository_ids=None
        )
        
        mock_v1_findings = []
        mock_v2_findings = []
        
        with patch.object(facade.v1_client, 'get_findings', return_value=mock_v1_findings) as mock_v1, \
             patch.object(facade.v2_client, 'get_all_finding_details', return_value=mock_v2_findings) as mock_v2, \
             patch('src.semgrep_client.log_json_debug'):
            
            v1_findings, v2_findings = facade.fetch_all_findings_with_details()
            
            # Verify V1 client was called with None (no filtering)
            mock_v1.assert_called_once_with("test-slug", None)
            
            assert v1_findings == []
            assert v2_findings == []


class TestRepositoryFilteringIntegration:
    """Integration tests for repository filtering."""
    
    def test_repository_filtering_reduces_api_calls(self):
        """Test that repository filtering reduces the number of V2 API calls."""
        # Create mock V1 findings (simulating 100 findings)
        mock_v1_findings = []
        for i in range(100):
            mock_finding = Mock(spec=SemgrepV1Finding)
            mock_finding.id = i + 1
            mock_finding.model_dump.return_value = {"id": i + 1, "test": "data"}
            mock_v1_findings.append(mock_finding)
        
        facade = SemgrepAPIFacade(
            api_token="test_token",
            deployment_slug="test-slug",
            deployment_id="test-id",
            repository_ids=[1, 2]  # Filter to specific repos
        )
        
        # Mock V2 findings
        mock_v2_findings = []
        
        with patch.object(facade.v1_client, 'get_findings', return_value=mock_v1_findings) as mock_v1, \
             patch.object(facade.v2_client, 'get_all_finding_details', return_value=mock_v2_findings) as mock_v2, \
             patch('src.semgrep_client.log_json_debug'):
            
            v1_findings, v2_findings = facade.fetch_all_findings_with_details()
            
            # V1 should be called with repository filter
            mock_v1.assert_called_once_with("test-slug", [1, 2])
            
            # V2 should be called with IDs from filtered V1 results
            expected_issue_ids = [str(i + 1) for i in range(100)]
            mock_v2.assert_called_once_with("test-id", expected_issue_ids)
            
            assert len(v1_findings) == 100
            assert v2_findings == []