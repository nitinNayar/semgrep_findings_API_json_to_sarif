# Technical Requirements Document
## Semgrep JSON to SARIF Format Converter

**Document Version:** 1.0  
**Date:** August 2025  
**Technology Stack:** Python  

---

## 1. Executive Summary

This document outlines the technical requirements for developing a python app that extracts  Semgrep security findings from Semgrep API using a combination of V1 & V2 in JSON format and then converts them to SARIF (Static Analysis Results Interchange Format) for integration with customer security toolchains. 

IMPORTANT NOTE: The solution MUST USE a combination of Semgrep API V1 and V2 for enhanced functionality including dataflow trace support and improved pagination. 
The Semgrep API V1 does not provide all the information that we require for findings details. The Semgrep API V2 will be used for getting the findings details and the dataflow

## 2. Business Requirements

### 2.1 Objective
Develop a python app that extracts  Semgrep security findings from Semgrep using a combination of Semgrep's V1 and V2 API in JSON format and then converts them to SARIF (Static Analysis Results Interchange Format) for integration with customer security toolchains

### 2.2 Key Deliverables
- Python-based converter application with Semgrep API V2 support
- Configuration-driven architecture
- Secure credential management (like Semgrep API Token) via environment variables
- OUTPUT MUST BE SARIF 2.1.0 compliant output with dataflow support
- Comprehensive handling of Semgrep's dataflow traces as SARIF threadFlows

## 3. Technical Architecture

### 3.1 System Overview
```
┌───────────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Semgrep API V1 & V2  │────▶│  Python          │────▶│  SARIF Output   │
│  (JSON Output)        │     │  Converter       │     │  (File/API)     │
└───────────────────────┘     └──────────────────┘     └─────────────────┘
                              │        │
                         ┌────▼────┐ ┌─▼─────┐
                         │  .env   │ │config │
                         │  file   │ │ .yaml │
                         └─────────┘ └───────┘
```

### 3.2 Component Design

#### Core Components:
1. **API Client Module** - Handles Semgrep API interactions
2. **Parser Module** - Processes JSON responses
3. **Transformer Module** - Converts JSON to SARIF
4. **Validator Module** - Validates SARIF output
5. **Configuration Manager** - Manages settings and credentials
6. **Output Handler** - Manages file/API output

## 4. Functional Requirements

### 4.0 Pseudo code:

(1) read the API token, Deployment_slug & Deployment_Id from the .evx file
(2) make a call to the Semgrep V1 API to get full list of findings: https://semgrep.dev/api/v1/deployments/{deployment_slug}/findings
(3) Write the output to a file in the /logs folder and name it findings_<deployment_id>_datetime- this will be useful for troubleshooting
(4) Iterate through all the findings in the previous API response and call the Semgrep V2 API to get the details using the "id" field - this is a Unique ID of this finding. This uses the Semgrep V2 API and the endpont is https://semgrep.dev/api/agent/deployments/{deploymentId}/issues/v2/{issueId}- write to an aggregate json object for all findings details
(5) Write the aggregate findings deatils with ALL findingins to a file in the /logs folder and name it findings_details_<deployment_id>_datetime- this will be useful for troubleshooting
(5) Then we call the mapping logic for JSON to SARIF

### 4.1 API Version Requirements
The converter MUST use a combination of Semgrep's V1 and V2 API, which provides:
- Enhanced dataflow trace information for taint analysis
- Improved pagination mechanisms (cursor and offset based)
- Richer metadata including confidence scores and vulnerability classifications
- Better error handling and rate limiting information
- Support for deployment-based organization of findings

### 4.2 Input Requirements

#### Semgrep API V1 & V2 Integration
- **Authentication**: Bearer token via `Authorization` header
- Support for paginated responses (cursor-based and offset-based)
- Handle rate limiting with exponential backoff
- Support batch processing of multiple projects/repositories

#### Key API V1 Endpoints
```
POST https://semgrep.dev/api/v1/deployments/{deployment_slug}/findings # List issues (same as findings) for a deployment
```

```json

{
  "findings": [
    {
      "assistant": {
        "autofix": {
          "explanation": "",
          "fix_code": "cookie.setHttpOnly(true);\nresponse.addCookie(cookie);"
        },
        "autotriage": {
          "reason": "The matched code is used for a non-security related feature.",
          "verdict": "false_positive"
        },
        "component": {
          "risk": "high",
          "tag": "user data"
        },
        "guidance": {
          "instructions": "1. Check if your project has any template engines installed such as EJS, Pug, or Mustache.\n    If not, install EJS, with a command such as `$ npm install ejs`.\n2. Create an EJS template: `const template = '<h2><%= user.id %></h2>'`\n3. <... example trimmed in API docs ...>",
          "summary": "Use a template rendering engine such as EJS instead of string concatenation."
        }
      },
      "categories": [
        "security"
      ],
      "confidence": "medium",
      "created_at": "2020-11-18 23:28:12.391807",
      "external_ticket": {
        "external_slug": "OPS-158",
        "id": 0,
        "linked_issue_ids": [
          0
        ],
        "url": "string"
      },
      "first_seen_scan_id": 1234,
      "id": 1234567,
      "line_of_code_url": "https://github.com/semgrep/semgrep/blob/39f95450a7d4d70e54c9edbd109bed8210a36889/src/core_cli/Core_CLI.ml#L1",
      "location": {
        "column": 8,
        "end_column": 16,
        "end_line": 124,
        "file_path": "frontend/src/corpComponents/Code.tsx",
        "line": 120
      },
      "match_based_id": "0f8c79a6f7e0ff2f908ff5bc366ae1548465069bae8892088051e1c3b4b12c6b8df37d5bcbb181eb868aa79f81f239d14bf2336d552786ab8ccdc7279adf07a6_1",
      "ref": "refs/pull/1234/merge",
      "relevant_since": "2020-11-18 23:28:12.391807",
      "repository": {
        "name": "semgrep",
        "url": "https://github.com/semgrep/semgrep"
      },
      "review_comments": [
        {
          "external_discussion_id": "af04762b69acfb74c8f9",
          "external_note_id": 123523
        }
      ],
      "rule": {
        "category": "security",
        "confidence": "high",
        "cwe_names": [
          "CWE-319: Cleartext Transmission of Sensitive Information"
        ],
        "message": "This link points to a plaintext HTTP URL. Prefer an encrypted HTTPS URL if possible.",
        "name": "html.security.plaintext-http-link.plaintext-http-link",
        "owasp_names": [
          "A03:2017 - Sensitive Data Exposure",
          "A02:2021 - Cryptographic Failures"
        ],
        "subcategories": [
          "vuln"
        ],
        "vulnerability_classes": [
          "Mishandled Sensitive Information"
        ]
      },
      "rule_message": "`ref` usage found. refs give direct DOM access and may create a possibility for XSS, which could cause\nsensitive information such as user cookies to be retrieved by an attacker. Instead, avoid direct DOM\nmanipulation or use DOMPurify to sanitize HTML before writing it into the page.\n",
      "rule_name": "typescript.react.security.audit.react-no-refs.react-no-refs",
      "severity": "medium",
      "sourcing_policy": {
        "id": 120,
        "name": "Default Policy",
        "slug": "default-policy"
      },
      "state": "unresolved",
      "state_updated_at": "2020-11-19 23:28:12.391807",
      "status": "open",
      "syntactic_id": "440eeface888e78afceac3dc7d4cc2cf",
      "triage_comment": "This finding is from the test repo",
      "triage_reason": "acceptable_risk",
      "triage_state": "untriaged",
      "triaged_at": "2020-11-19 23:28:12.391807"
    }
  ]
}
```


#### Key API V2 Endpoints
```
GET https://semgrep.dev/api/agent/deployments/{deploymentId}/issues/v2/{issueId} 
```

RESPONSE:
```json

{
  "id": "string",
  "createdAt": "2019-08-24T14:15:22Z",
  "ref": "string",
  "syntacticId": "string",
  "matchBasedId": "string",
  "ruleId": "string",
  "status": "ISSUE_STATUS_FIXED",
  "repository": {
    "name": "string",
    "id": "string",
    "type": "SCM_TYPE_GITHUB",
    "primaryRef": {
      "id": "string",
      "ref": "string"
    }
  },
  "firstSeenScan": {
    "id": "string",
    "meta": {}
  },
  "triageState": "FINDING_TRIAGE_STATE_UNTRIAGED",
  "triageReason": "FINDING_TRIAGE_REASON_FALSE_POSITIVE",
  "relevantSince": "2019-08-24T14:15:22Z",
  "aggregateState": "AGGREGATE_ISSUE_STATE_OPEN",
  "note": "string",
  "externalTicket": {
    "url": "string",
    "externalSlug": "string",
    "id": "string",
    "linkedIssueIds": [
      "string"
    ]
  },
  "vulnGroupKey": "string",
  "isBlocking": true,
  "autotriage": {
    "id": "string",
    "issueId": "string",
    "verdict": "VERDICT_TRUE_POSITIVE",
    "reason": "string",
    "feedback": {
      "autotriageId": "string",
      "rating": "RATING_GOOD"
    },
    "matchBasedId": "string",
    "memoryIdsReferenced": [
      "string"
    ],
    "memoryIdsRendered": [
      "string"
    ]
  },
  "aiTags": {
    "id": "string",
    "path": "string",
    "tags": "string",
    "sensitivity": "SENSITIVITY_HIGH_SENSITIVITY"
  },
  "lineOfCodeUrl": "string",
  "codeSnippet": "string",
  "dataflowTrace": {
    "taintSource": [
      {
        "path": "string",
        "start": {
          "line": "string",
          "col": "string",
          "offset": "string"
        },
        "end": {
          "line": "string",
          "col": "string",
          "offset": "string"
        },
        "locationUrl": "string"
      }
    ],
    "intermediateVars": [
      {
        "path": "string",
        "start": {
          "line": "string",
          "col": "string",
          "offset": "string"
        },
        "end": {
          "line": "string",
          "col": "string",
          "offset": "string"
        },
        "locationUrl": "string"
      }
    ],
    "taintSink": [
      {
        "path": "string",
        "start": {
          "line": "string",
          "col": "string",
          "offset": "string"
        },
        "end": {
          "line": "string",
          "col": "string",
          "offset": "string"
        },
        "locationUrl": "string"
      }
    ]
  },
  "commitUrl": "string",
  "activityHistory": [
    {
      "date": "2019-08-24T14:15:22Z",
      "title": "string",
      "triageReason": "string",
      "note": "string",
      "actor": "string",
      "historyType": "HISTORY_TYPE_STATUS"
    }
  ],
  "relatedIssues": [
    {
      "id": "string",
      "ref": "string",
      "pullRequestId": "string",
      "aggregateState": "AGGREGATE_ISSUE_STATE_OPEN"
    }
  ],
  "remediation": {
    "issueId": "string",
    "matchBasedId": "string",
    "autofix": {
      "id": "string",
      "fixCode": "string",
      "fixDiff": "string",
      "explanation": "string",
      "url": "string"
    },
    "guidance": {
      "id": "string",
      "summary": "string",
      "guidanceText": "string",
      "memoryIdsUsed": [
        "string"
      ]
    }
  },
  "lastSeenScan": {
    "id": "string",
    "meta": {}
  },
  "filePath": "string",
  "line": 0,
  "endLine": 0,
  "column": 0,
  "endColumn": 0,
  "severity": "SEVERITY_HIGH",
  "message": "string",
  "rulePath": "string",
  "confidence": "CONFIDENCE_HIGH",
  "ruleUrl": "string",
  "ruleReferences": [
    "string"
  ],
  "ruleOrigin": "RULE_ORIGIN_CUSTOM",
  "ruleHashId": "string",
  "ruleCweNames": [
    "string"
  ],
  "ruleOwaspNames": [
    "string"
  ],
  "ruleset": "string",
  "policySlug": "string",
  "category": "string",
  "ruleSupersededBy": [
    {
      "product": "RULE_TYPE_SAST",
      "rulePath": "string"
    }
  ],
  "issueType": "ISSUE_TYPE_SAST",
  "issueParentId": "string",
  "ticketAttempts": [
    {
      "attemptedAt": "2019-08-24T14:15:22Z",
      "responseMessage": "string"
    }
  ],
  "sastAttributes": {},
  "scaAttributes": {
    "severity": "SEVERITY_HIGH",
    "vulnDatabaseIdentifier": "string",
    "reachability": "REACHABILITY_CONDITIONALLY_REACHABLE",
    "reachableCondition": "string",
    "cwes": [
      "string"
    ],
    "foundDependency": {
      "package": "string",
      "version": "string",
      "transitivity": "UNKNOWN_TRANSITIVITY",
      "lockfileLineUrl": "string",
      "filePath": "string",
      "ecosystem": "no_package_manager",
      "manifestFilePath": "string"
    },
    "fixRecommendations": [
      {
        "package": "string",
        "version": "string"
      }
    ],
    "bestFix": {
      "package": "string",
      "version": "string"
    },
    "epssScore": {
      "score": 0.1,
      "percentile": 0.1,
      "updatedAt": "2019-08-24T14:15:22Z",
      "categorization": "EPSS_PROBABILITY_LOW"
    },
    "rulePublishDate": "2019-08-24T14:15:22Z",
    "scaRuleKind": "SCA_RULE_KIND_REACHABLE",
    "scaMatchInfo": {
      "matchKind": "SCA_MATCH_KIND_LOCKFILE_ONLY",
      "analyzedPackages": [
        {
          "package": "string",
          "version": "string",
          "transitivity": "UNKNOWN_TRANSITIVITY",
          "lockfileLineUrl": "string",
          "filePath": "string",
          "ecosystem": "no_package_manager",
          "manifestFilePath": "string"
        }
      ],
      "transitiveMatches": [
        {
          "dependency": {
            "package": "string",
            "version": "string",
            "transitivity": "UNKNOWN_TRANSITIVITY",
            "lockfileLineUrl": "string",
            "filePath": "string",
            "ecosystem": "no_package_manager",
            "manifestFilePath": "string"
          },
          "path": "string",
          "line": "string"
        }
      ]
    }
  },
  "secretsAttributes": {
    "validationState": "VALIDATION_STATE_CONFIRMED_VALID",
    "secretType": "string",
    "historicalInfo": {
      "gitCommit": "string",
      "gitCommitTimestamp": "2019-08-24T14:15:22Z",
      "gitBlob": "string"
    }
  },
  "subcategories": [
    "string"
  ],
  "refUrl": "string",
  "codeowners": [
    {
      "id": "string",
      "name": "string",
      "isTeam": true,
      "members": [
        {}
      ]
    }
  ],
  "codeSnippets": [
    {
      "path": "string",
      "content": "string"
    }
  ]
}
```

### 4.3 Data Mapping Specifications

| Semgrep V2 Field | SARIF Field | Transformation Logic |
|------------------|-------------|---------------------|
| rule_id | ruleId | Direct mapping |
| rule_name | rules[].name | Store in rule metadata |
| path | physicalLocation.artifactLocation.uri | Normalize path format |
| line/column | physicalLocation.region.startLine/startColumn | Direct mapping |
| end_line/end_column | physicalLocation.region.endLine/endColumn | Direct mapping |
| message | message.text | Direct mapping |
| severity | level | Map: high→error, medium→warning, low→note |
| confidence | properties.confidence | Store in property bag |
| category | properties.category | Store in property bag |
| vulnerability_class | taxa | Map to CWE/OWASP taxonomies |
| metadata.cwe | taxa[].id | Create taxonomy references |
| metadata.owasp | taxa[].id | Create taxonomy references |
| dataflow_trace | threadFlows | Transform to SARIF codeFlow format |
| fix_recommendations | fixes | Transform to SARIF fix objects |
| triaged/state | suppressions | If triaged, create suppression |

#### Dataflow Trace Transformation
For findings with dataflow traces, transform to SARIF codeFlows:
```json
{
  "codeFlows": [{
    "message": {"text": "Tainted data flow from user input to SQL query"},
    "threadFlows": [{
      "locations": [
        {
          "location": { /* source location */ },
          "kinds": ["source", "taint"],
          "nestingLevel": 0,
          "executionOrder": 1,
          "importance": "essential"
        },
        {
          "location": { /* intermediate location */ },
          "kinds": ["intermediate"],
          "nestingLevel": 1,
          "executionOrder": 2,
          "importance": "important"
        },
        {
          "location": { /* sink location */ },
          "kinds": ["sink"],
          "nestingLevel": 1,
          "executionOrder": 3,
          "importance": "essential"
        }
      ]
    }]
  }]
}

## 5. Configuration Requirements

### 5.1 Configuration File Structure (config.yaml)

```yaml
# Application Configuration
app:
  name: "semgrep-sarif-converter"
  version: "1.0.0"
  log_level: "INFO"

# Semgrep Configuration
semgrep:
  base_url: "https://semgrep.dev/api/v2"
  timeout: 30
  max_retries: 3
  rate_limit:
    requests_per_second: 10
    burst_size: 20

# Input Configuration
input:
  mode: "api"  # Options: api, file
  file_path: "./input/semgrep-results.json"
  deployment_id: "${SEMGREP_DEPLOYMENT_ID}"
  
# Output Configuration  
output:
  format: "sarif"
  sarif_version: "2.1.0"
  destination: "file"  # Options: file, api, stdout
  file_path: "./output/results.sarif"
  api_endpoint: "${TARGET_SARIF_ENDPOINT}"
  include_suppressed: false
  
# Processing Options
processing:
  batch_size: 100
  parallel_workers: 4
  validate_output: true
  
# Filtering Rules
filters:
  severities: ["ERROR", "WARNING"]
  exclude_paths:
    - "test/**"
    - "vendor/**"
  include_rules: []
  exclude_rules: []
```

### 5.2 Environment Variables (.env)

```bash
# Semgrep API Credentials
SEMGREP_API_TOKEN=sg_token_xxxxxxxxxxxxx
SEMGREP_DEPLOYMENT_ID=deployment_id_here
SEMGREP_ORG_NAME=organization_name


# Optional: Override configuration
CONFIG_FILE_PATH=./config/production.yaml
LOG_FILE_PATH=./logs/converter.log
```

## 6. Security Requirements

### 6.1 Credential Management
- All sensitive credentials stored in `.env` file
- `.env` file must be excluded from version control
- Support for environment variable override
- Implement secure credential rotation mechanism

### 6.2 API Security
- TLS 1.2+ for all API communications
- API key validation before processing
- Request signing where applicable
- Implement retry with exponential backoff

### 6.3 Data Security
- Sanitize all file paths to prevent directory traversal
- Validate JSON input structure
- Implement output validation against SARIF schema
- Log sensitive data masking

## 7. Implementation Guidelines

### 7.1 Project Structure
```
semgrep-sarif-converter/
├── src/
│   ├── __init__.py
│   ├── main.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── semgrep_client.py
│   │   └── target_client.py
│   ├── converters/
│   │   ├── __init__.py
│   │   ├── json_parser.py
│   │   ├── sarif_transformer.py
│   │   └── validators.py
│   ├── config/
│   │   ├── __init__.py
│   │   └── config_manager.py
│   └── utils/
│       ├── __init__.py
│       ├── logger.py
│       └── helpers.py
├── tests/
│   ├── test_converter.py
│   ├── test_api.py
│   └── fixtures/
├── config/
│   ├── config.yaml
│   └── config.schema.json
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
└── Dockerfile
```

### 7.2 Dependencies (requirements.txt)
```
# Core Dependencies
python>=3.9
requests>=2.31.0
pyyaml>=6.0
python-dotenv>=1.0.0
jsonschema>=4.19.0

# Data Processing
pydantic>=2.0.0
jmespath>=1.0.1

# Logging and Monitoring
structlog>=23.1.0
python-json-logger>=2.0.7

# Testing
pytest>=7.4.0
pytest-cov>=4.1.0
pytest-mock>=3.11.1

# Development
black>=23.7.0
flake8>=6.1.0
mypy>=1.5.0
pre-commit>=3.3.3
```

### 7.3 Core Implementation Classes

```python
# Example structure for main converter class
class SemgrepToSarifConverter:
    def __init__(self, config_path: str, env_path: str):
        """Initialize converter with configuration"""
        
    def authenticate_semgrep_v2(self) -> dict:
        """Authenticate with Semgrep API V2 using Bearer token"""
        
    def fetch_semgrep_findings(self, deployment_slug: str, cursor: str = None) -> dict:
        """
        Fetch findings from Semgrep API V2 with pagination support
        Handles both cursor-based and offset-based pagination
        """
        
    def parse_v2_findings(self, json_data: dict) -> list:
        """Parse and validate V2 API JSON structure"""
        
    def transform_dataflow_to_codeflow(self, dataflow_trace: dict) -> dict:
        """Convert Semgrep dataflow trace to SARIF codeFlow format"""
        
    def transform_to_sarif(self, findings: list) -> dict:
        """Convert findings to SARIF format with dataflow support"""
        
    def validate_sarif(self, sarif_data: dict) -> bool:
        """Validate SARIF against schema 2.1.0"""
        
    def handle_pagination(self, initial_response: dict) -> list:
        """Handle V2 API pagination (cursor and offset based)"""
        
    def output_results(self, sarif_data: dict) -> None:
        """Output SARIF to configured destination"""
```

#### API V2 Authentication Example
```python
import requests
from typing import Optional, Dict, List

class SemgrepV2Client:
    def __init__(self, api_token: str, base_url: str = "https://semgrep.dev/api/v2"):
        self.api_token = api_token
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
    
    def get_findings(self, deployment_slug: str, 
                    cursor: Optional[str] = None,
                    page_size: int = 100) -> Dict:
        """
        Fetch findings with pagination support
        """
        params = {"page_size": page_size}
        if cursor:
            params["cursor"] = cursor
        
        response = requests.get(
            f"{self.base_url}/deployments/{deployment_slug}/findings",
            headers=self.headers,
            params=params
        )
        response.raise_for_status()
        return response.json()
    
    def get_all_findings(self, deployment_slug: str) -> List[Dict]:
        """
        Fetch all findings handling pagination automatically
        """
        all_findings = []
        cursor = None
        
        while True:
            response = self.get_findings(deployment_slug, cursor)
            all_findings.extend(response.get("findings", []))
            
            if not response.get("has_more", False):
                break
                
            cursor = response.get("cursor")
        
        return all_findings
```

## 8. Error Handling Requirements

### 8.1 Error Categories
- **API Errors**: Connection failures, authentication errors, rate limiting
- **Data Errors**: Invalid JSON, missing required fields, type mismatches
- **Configuration Errors**: Missing config file, invalid settings
- **Output Errors**: File write failures, API submission errors
- **V2 Specific Errors**: Invalid deployment slug, cursor expiration, pagination limits

### 8.2 Error Response Format
```json
{
  "error": {
    "code": "CONVERSION_ERROR",
    "message": "Failed to convert Semgrep findings",
    "details": {
      "timestamp": "2025-08-30T10:00:00Z",
      "trace_id": "uuid-here",
      "context": {
        "api_version": "v2",
        "endpoint": "/deployments/{slug}/findings"
      }
    }
  }
}
```

### 8.3 API V2 Specific Error Handling
```python
def handle_api_v2_errors(response):
    """Handle Semgrep API V2 specific errors"""
    if response.status_code == 401:
        raise AuthenticationError("Invalid API token")
    elif response.status_code == 403:
        raise AuthorizationError("Access denied to deployment")
    elif response.status_code == 404:
        raise NotFoundError("Deployment or resource not found")
    elif response.status_code == 429:
        retry_after = response.headers.get('Retry-After', 60)
        raise RateLimitError(f"Rate limited. Retry after {retry_after} seconds")
    elif response.status_code >= 500:
        raise ServerError("Semgrep API server error")
```


## 10. Testing Requirements

### 10.1 Test Coverage
- Unit tests: Minimum 80% code coverage
- Integration tests for API interactions
- End-to-end tests for complete workflow
- Performance tests for large datasets

### 10.2 Test Scenarios
1. Valid JSON to SARIF conversion
2. Handling of malformed JSON input
3. API authentication failures
4. Rate limiting behavior
5. Large dataset processing
6. Configuration validation
7. SARIF schema compliance
8. **V2 API Specific Tests:**
   - Cursor-based pagination handling
   - Dataflow trace to codeFlow conversion
   - Multiple deployment handling
   - Cursor expiration and refresh
   - Severity and confidence mapping
   - CWE/OWASP taxonomy extraction

## 11. Monitoring and Logging

Create a logs folder and write all /logs to that folder

### 11.1 Logging Requirements
- Structured logging in JSON format
- Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
- Include correlation IDs for tracing
- Mask sensitive data in logs

### 11.2 Metrics to Track
- Conversion success/failure rates
- Processing time per finding
- API response times
- Memory usage
- Error frequency by type


## 13. Documentation Requirements

### 13.1 Required Documentation
- API documentation (OpenAPI/Swagger)
- Configuration guide
- Deployment guide
- Troubleshooting guide
- Security best practices

### 13.2 Code Documentation
- Docstrings for all public methods
- Type hints for all functions
- README with quick start guide
- CHANGELOG for version tracking

## 14. Acceptance Criteria

### 14.1 Functional Criteria
- ✅ Successfully converts Semgrep JSON to valid SARIF 2.1.0
- ✅ Handles all Semgrep severity levels
- ✅ Preserves all metadata from original findings
- ✅ Validates output against SARIF schema

### 14.2 Non-Functional Criteria
- ✅ Processes 1000 findings in < 10 seconds
- ✅ Maintains 99.9% uptime in production
- ✅ Zero credential leaks in logs
- ✅ Passes security audit


## 16. Appendix

### A. SARIF Schema Reference
- [SARIF 2.1.0 Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [SARIF Tutorials by Microsoft](https://github.com/microsoft/sarif-tutorials)

### B. Semgrep API V2 Documentation
- [Semgrep API V2 OpenAPI Specification](https://semgrep.dev/api/v2/docs/)
- [Semgrep API Authentication Guide](https://semgrep.dev/docs/semgrep-appsec-platform/semgrep-api)
- [API Pagination Guide](https://semgrep.dev/docs/kb/integrations/pagination)

### C. Sample Conversion Example
Available in project repository under `/examples`

### D. Dataflow to CodeFlow Mapping Reference
- Source nodes: `kinds: ["source", "taint"]`
- Intermediate nodes: `kinds: ["intermediate"]`  
- Sink nodes: `kinds: ["sink"]`
- Include `executionOrder`, `nestingLevel`, and `importance` properties
- Reference: SARIF v2.1.0 Section 3.38 (threadFlowLocation)

---

**Document Status:** DRAFT  
**Next Review Date:** [To be determined]  
**Approval Required From:** Engineering Lead, Security Team