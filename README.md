# Semgrep Findings to SARIF Converter using Semgrep API

A Python application that extracts Semgrep security findings using Semgrep APIs and converts them to SARIF (Static Analysis Results Interchange Format) 2.1.0.

## Features

### Core Functionality
- **Dual API Integration**: Uses Semgrep V1 API for findings list and V2 (Experimental) API for detailed findings with dataflow traces
- **SARIF 2.1.0 Compliance**: Generates valid SARIF output with schema validation and dataflow support (threadFlows)
- **Environment Configuration**: Simple configuration via `.env` file with extensive customization options
- **Dataflow Mapping**: Converts Semgrep dataflow traces to SARIF threadFlows/codeFlows
- **Field Mapping**: Complete mapping of Semgrep fields to SARIF format per technical specifications
- **Semgrep AI Analysis Mapping**: Integrates Semgrep AI Assistant metadata for true/false positive detection
- **Auto-Triage Support**: Processes AI verdict data (VERDICT_TRUE_POSITIVE/VERDICT_FALSE_POSITIVE)
- **Smart Suppressions**: Automatically handles false positives via SARIF suppressions based on Semgrep AI Assistant generated Triage Guidance
- **Fix Recommendations**: Maps Semgrep AI Assistant generated fix suggestions to SARIF fixes format

### Repository Management
- **Repository Filtering**: Filter findings by specific repository IDs for targeted analysis
- **Multi-Repository Support**: Process findings from selected repositories or all repositories
- **Dynamic Configuration**: Repository filtering configurable via environment variables

### Advanced Logging & Debugging
- **Debug Mode**: Comprehensive debug logging with detailed API call tracking
- **Structured Logging**: Multi-level logging with both console and file outputs
- **Intermediate JSON Dumps**: Complete API responses saved for troubleshooting
- **Request/Response Timing**: Detailed timing and status code logging for each API call

### Configuration & Security
- **Dynamic Filename Generation**: Automatic timestamped SARIF output with deployment information
- **Pagination Configuration**: Configurable page sizes and limits for large datasets
- **Security Hardening**: Filename sanitization and path traversal protection
- **Rate Limit Handling**: Automatic retry with exponential backoff for rate limits
- **Authentication Management**: Secure token handling with comprehensive error handling

### Error Handling & Resilience
- **Comprehensive Exception Handling**: Specific exceptions for authentication, rate limits, not found, etc.
- **HTTP Session Management**: Configured with retry strategies and timeout handling
- **Schema Validation**: Online SARIF 2.1.0 schema validation with detailed error reporting
- **Graceful Degradation**: Continues processing even with partial API failures

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd semgrep_findings_API_json_to_sarif
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your Semgrep credentials
   ```

## Configuration

Create a `.env` file with the following variables:

### Required Variables
```bash
# Semgrep API credentials
SEMGREP_API_TOKEN=xxxxxxxxxxxxx
SEMGREP_DEPLOYMENT_SLUG=your-deployment-slug  
SEMGREP_DEPLOYMENT_ID=your-deployment-id
```

### Optional Configuration

#### Output Configuration
```bash
# Output file path (default: auto-generated with timestamp)
# Format: ./output/DEPLOYMENT_ID__YYYYMMDD_HHMMSS.sarif
OUTPUT_SARIF_PATH=./output/results.sarif
```

#### Repository Filtering
```bash
# Enable repository filtering (default: false)
FILTER_FINDINGS_FOR_SPECIFIC_REPO_IDS=false

# Comma-separated list of repository IDs to include (required when filtering is enabled)
# Example: LIST_OF_REPO_IDS=1,2,3,5,8
LIST_OF_REPO_IDS=
```

#### Debug and Logging
```bash
# Enable detailed debug logging with API call tracking (default: false)
DEBUG=true
```

#### Pagination Configuration
```bash
# Number of findings per API page (default: 100)
SEMGREP_PAGE_SIZE=100

# Maximum pages to process as safety limit (default: 1000)
SEMGREP_MAX_PAGES=1000
```

### Getting Semgrep Credentials

1. **API Token**: Get from [Semgrep App Settings](https://semgrep.dev/orgs/-/settings/tokens)
2. **Deployment Slug**: Get from [Semgrep App Settings](https://semgrep.dev/orgs/-/settings/general/identifiers)
3. **Deployment ID**: Get from [Semgrep App Settings](https://semgrep.dev/orgs/-/settings/general/identifiers)

## Debug Mode

Enable comprehensive debug logging for troubleshooting and monitoring:

```bash
DEBUG=true
```

### Debug Features

#### API Call Tracking
- **Real-time Monitoring**: Thread-safe counter tracks all V1/V2 API calls
- **Performance Metrics**: Request timing and response status codes
- **Call Numbering**: Sequential numbering of API calls for correlation
- **Console Output**: Live debug output during execution

Example debug output:
```
DEBUG: V1 API Call #1: GET https://semgrep.dev/api/v1/deployments/example/findings
DEBUG: V1 API Call #1 Response: 200 (1247.3ms)
DEBUG: V2 API Call #1: GET https://semgrep.dev/api/agent/deployments/123/issues/v2/456
DEBUG: V2 API Call #1 Response: 200 (892.1ms)
```

#### Enhanced Logging
- **Structured Logging**: Both console and file outputs with different detail levels
- **Log File Creation**: Timestamped log files in `/logs/converter_YYYYMMDD_HHMMSS.log`
- **Request Correlation**: Unique correlation IDs for tracing requests
- **Error Context**: Detailed error information with stack traces

#### JSON Debug Dumps
All API responses are automatically saved for analysis:
- `/logs/findings_<deployment_id>_<timestamp>.json` - V1 API response
- `/logs/findings_details_<deployment_id>_<timestamp>.json` - Aggregated V2 responses

## Usage

### Basic Usage

```bash
python src/main.py
```

The converter will:
1. Read configuration from `.env` file
2. Apply repository filtering (if enabled)
3. Fetch findings list from Semgrep V1 API
4. Log V1 response to `/logs/findings_<deployment_id>_<timestamp>.json`
5. Fetch detailed findings from Semgrep V2 API for each finding (includes AI metadata)
6. Log aggregated V2 response to `/logs/findings_details_<deployment_id>_<timestamp>.json`
7. Transform findings to SARIF 2.1.0 format with AI analysis integration
8. Write SARIF output with auto-generated filename (format: `deployment_id__YYYYMMDD_HHMMSS.sarif`)

### Repository Filtering Examples

#### Process All Repositories (Default)
```bash
# .env configuration
FILTER_FINDINGS_FOR_SPECIFIC_REPO_IDS=false
# LIST_OF_REPO_IDS not required
```

#### Filter for Specific Repositories
```bash
# .env configuration
FILTER_FINDINGS_FOR_SPECIFIC_REPO_IDS=true
LIST_OF_REPO_IDS=1,2,3,5,8

# Run converter
python src/main.py
```

This will only process findings from repositories with IDs: 1, 2, 3, 5, and 8.

