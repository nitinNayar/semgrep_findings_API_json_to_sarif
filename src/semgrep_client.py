"""Semgrep API client for V1 and V2 endpoints."""

import logging
import time
from typing import List, Optional, Dict, Any
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import RequestException, Timeout, HTTPError
from urllib3.util.retry import Retry

from .models import SemgrepV1Response, SemgrepV1Finding, SemgrepV2Finding
from .utils import log_json_debug


class SemgrepAPIError(Exception):
    """Base exception for Semgrep API errors."""
    pass


class AuthenticationError(SemgrepAPIError):
    """Authentication failed."""
    pass


class RateLimitError(SemgrepAPIError):
    """Rate limit exceeded."""
    
    def __init__(self, message: str, retry_after: Optional[int] = None):
        super().__init__(message)
        self.retry_after = retry_after


class NotFoundError(SemgrepAPIError):
    """Resource not found."""
    pass


class SemgrepClient:
    """Base client for Semgrep API interactions."""
    
    def __init__(self, api_token: str, base_url: str = "https://semgrep.dev/api"):
        """Initialize the Semgrep API client.
        
        Args:
            api_token: Semgrep API token (should start with 'sg_')
            base_url: Base URL for Semgrep API
        """
        self.api_token = api_token
        self.base_url = base_url.rstrip('/')
        self.logger = logging.getLogger(__name__)
        
        # Set up session with retries and timeouts
        self.session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set default headers
        self.session.headers.update({
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
            "User-Agent": "semgrep-sarif-converter/1.0.0"
        })
        
        # Default timeout (connect, read)
        self.timeout = (10, 30)
    
    def _handle_response(self, response: requests.Response) -> Dict[str, Any]:
        """Handle API response and raise appropriate exceptions.
        
        Args:
            response: HTTP response object
            
        Returns:
            Parsed JSON response
            
        Raises:
            AuthenticationError: For 401 responses
            NotFoundError: For 404 responses  
            RateLimitError: For 429 responses
            SemgrepAPIError: For other error responses
        """
        try:
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                raise AuthenticationError("Invalid API token or insufficient permissions")
            elif response.status_code == 404:
                raise NotFoundError("Resource not found (check deployment slug/ID)")
            elif response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 60))
                raise RateLimitError(f"Rate limit exceeded", retry_after)
            else:
                error_msg = f"API request failed with status {response.status_code}"
                try:
                    error_detail = response.json()
                    if 'message' in error_detail:
                        error_msg += f": {error_detail['message']}"
                except:
                    error_msg += f": {response.text[:200]}"
                raise SemgrepAPIError(error_msg)
        except ValueError as e:
            raise SemgrepAPIError(f"Invalid JSON response: {e}")
    
    def _make_request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """Make HTTP request with error handling and retries.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            **kwargs: Additional arguments for requests
            
        Returns:
            Parsed JSON response
        """
        kwargs.setdefault('timeout', self.timeout)
        
        try:
            self.logger.debug(f"Making {method} request to: {url}")
            response = self.session.request(method, url, **kwargs)
            return self._handle_response(response)
        except RateLimitError as e:
            self.logger.warning(f"Rate limited, retrying after {e.retry_after} seconds")
            time.sleep(e.retry_after)
            response = self.session.request(method, url, **kwargs)
            return self._handle_response(response)
        except Timeout as e:
            raise SemgrepAPIError(f"Request timeout: {e}")
        except RequestException as e:
            raise SemgrepAPIError(f"Request failed: {e}")


class SemgrepV1Client(SemgrepClient):
    """Client for Semgrep V1 API endpoints."""
    
    def __init__(self, api_token: str):
        """Initialize V1 API client."""
        super().__init__(api_token, "https://semgrep.dev/api")
    
    def get_findings(self, deployment_slug: str, repository_ids: Optional[List[int]] = None) -> List[SemgrepV1Finding]:
        """Fetch findings for a deployment using V1 API.
        
        Args:
            deployment_slug: Deployment slug identifier
            repository_ids: Optional list of repository IDs to filter by
            
        Returns:
            List of V1 findings
        """
        url = f"{self.base_url}/v1/deployments/{deployment_slug}/findings"
        
        # Add repository_ids query parameter if provided
        params = {}
        if repository_ids:
            # Convert list of integers to comma-separated string
            params['repository_ids'] = ','.join(map(str, repository_ids))
            self.logger.info(f"Fetching V1 findings for deployment: {deployment_slug}, filtered by repository IDs: {repository_ids}")
        else:
            self.logger.info(f"Fetching V1 findings for deployment: {deployment_slug} (all repositories)")
        
        try:
            response_data = self._make_request("GET", url, params=params)
            
            # Parse response using Pydantic model
            v1_response = SemgrepV1Response(**response_data)
            
            if repository_ids:
                self.logger.info(f"Retrieved {len(v1_response.findings)} findings from V1 API (filtered by {len(repository_ids)} repository IDs)")
            else:
                self.logger.info(f"Retrieved {len(v1_response.findings)} findings from V1 API")
            
            return v1_response.findings
        except Exception as e:
            self.logger.error(f"Failed to fetch V1 findings: {e}")
            raise


class SemgrepV2Client(SemgrepClient):
    """Client for Semgrep V2 API endpoints."""
    
    def __init__(self, api_token: str):
        """Initialize V2 API client."""
        super().__init__(api_token, "https://semgrep.dev/api/agent")
    
    def get_finding_details(self, deployment_id: str, issue_id: str) -> SemgrepV2Finding:
        """Fetch detailed finding information using V2 API.
        
        Args:
            deployment_id: Deployment ID
            issue_id: Issue/finding ID
            
        Returns:
            Detailed V2 finding
        """
        url = f"{self.base_url}/deployments/{deployment_id}/issues/v2/{issue_id}"
        
        self.logger.debug(f"Fetching V2 details for issue: {issue_id}")
        
        try:
            response_data = self._make_request("GET", url)
            
            # Parse response using Pydantic model
            v2_finding = SemgrepV2Finding(**response_data)
            
            return v2_finding
        except Exception as e:
            self.logger.error(f"Failed to fetch V2 finding details for issue {issue_id}: {e}")
            raise
    
    def get_all_finding_details(
        self, 
        deployment_id: str, 
        issue_ids: List[str],
        log_progress: bool = True
    ) -> List[SemgrepV2Finding]:
        """Fetch detailed information for multiple findings.
        
        Args:
            deployment_id: Deployment ID
            issue_ids: List of issue/finding IDs
            log_progress: Whether to log progress for large batches
            
        Returns:
            List of detailed V2 findings
        """
        detailed_findings = []
        total_issues = len(issue_ids)
        
        self.logger.info(f"Fetching V2 details for {total_issues} findings")
        
        for i, issue_id in enumerate(issue_ids, 1):
            try:
                finding = self.get_finding_details(deployment_id, str(issue_id))
                detailed_findings.append(finding)
                
                if log_progress and i % 10 == 0:
                    self.logger.info(f"Progress: {i}/{total_issues} findings processed")
                    
            except Exception as e:
                self.logger.warning(f"Failed to fetch details for issue {issue_id}: {e}")
                # Continue processing other findings even if one fails
                continue
        
        self.logger.info(f"Successfully retrieved details for {len(detailed_findings)}/{total_issues} findings")
        
        return detailed_findings


class SemgrepAPIFacade:
    """Facade that combines V1 and V2 API clients for the complete workflow."""
    
    def __init__(self, api_token: str, deployment_slug: str, deployment_id: str, repository_ids: Optional[List[int]] = None):
        """Initialize the API facade.
        
        Args:
            api_token: Semgrep API token
            deployment_slug: Deployment slug for V1 API
            deployment_id: Deployment ID for V2 API
            repository_ids: Optional list of repository IDs to filter by
        """
        self.deployment_slug = deployment_slug
        self.deployment_id = deployment_id
        self.repository_ids = repository_ids
        self.logger = logging.getLogger(__name__)
        
        self.v1_client = SemgrepV1Client(api_token)
        self.v2_client = SemgrepV2Client(api_token)
    
    def fetch_all_findings_with_details(self) -> tuple[List[SemgrepV1Finding], List[SemgrepV2Finding]]:
        """Execute the complete findings fetch workflow.
        
        Following the pseudo code from requirements:
        1. V1 API call to get findings list
        2. Log V1 response to debug file
        3. V2 API calls to get detailed findings
        4. Log aggregated V2 response to debug file
        
        Returns:
            Tuple of (V1 findings list, V2 detailed findings list)
        """
        self.logger.info("Starting complete findings fetch workflow")
        
        # Step 1 & 2: V1 API call and logging
        if self.repository_ids:
            self.logger.info(f"Step 1: Fetching V1 findings list (filtered by repository IDs: {self.repository_ids})")
        else:
            self.logger.info("Step 1: Fetching V1 findings list (all repositories)")
        v1_findings = self.v1_client.get_findings(self.deployment_slug, self.repository_ids)
        
        # Log V1 response for debugging
        v1_data = [finding.model_dump() for finding in v1_findings]
        log_json_debug({"findings": v1_data}, f"findings_{self.deployment_id}")
        
        # Step 3 & 4: V2 API calls and logging
        self.logger.info("Step 2: Fetching V2 detailed findings")
        issue_ids = [str(finding.id) for finding in v1_findings]
        v2_findings = self.v2_client.get_all_finding_details(self.deployment_id, issue_ids)
        
        # Log aggregated V2 response for debugging
        v2_data = [finding.model_dump() for finding in v2_findings]
        log_json_debug(v2_data, f"findings_details_{self.deployment_id}")
        
        self.logger.info(f"Workflow complete: {len(v1_findings)} V1 findings, {len(v2_findings)} V2 details")
        
        return v1_findings, v2_findings