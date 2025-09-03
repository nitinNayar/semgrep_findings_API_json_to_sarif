# Semgrep to SARIF Converter

A Python application that extracts Semgrep security findings using both V1 and V2 APIs and converts them to SARIF (Static Analysis Results Interchange Format) 2.1.0.

## Features

- **Dual API Integration**: Uses Semgrep V1 API for findings list and V2 API for detailed findings with dataflow traces
- **SARIF 2.1.0 Compliance**: Generates valid SARIF output with dataflow support (threadFlows)
- **Environment Configuration**: Simple configuration via `.env` file
- **Debug Logging**: Comprehensive logging with intermediate JSON files for troubleshooting
- **Dataflow Mapping**: Converts Semgrep dataflow traces to SARIF threadFlows/codeFlows
- **Field Mapping**: Complete mapping of Semgrep fields to SARIF format per technical specifications

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd semgrep-sarif-converter
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

```bash
# Required: Semgrep API credentials
SEMGREP_API_TOKEN=sg_token_xxxxxxxxxxxxx
SEMGREP_DEPLOYMENT_SLUG=your-deployment-slug  
SEMGREP_DEPLOYMENT_ID=your-deployment-id

# Optional: Output configuration
OUTPUT_SARIF_PATH=./output/results.sarif
```

### Getting Semgrep Credentials

1. **API Token**: Get from [Semgrep App Settings](https://semgrep.dev/orgs/-/settings/tokens)
2. **Deployment Slug**: Found in your Semgrep deployment URL
3. **Deployment ID**: Available in Semgrep deployment settings

## Usage

### Basic Usage

```bash
python src/main.py
```

The converter will:
1. Read configuration from `.env` file
2. Fetch findings list from Semgrep V1 API
3. Log V1 response to `/logs/findings_<deployment_id>_<timestamp>.json`
4. Fetch detailed findings from Semgrep V2 API for each finding
5. Log aggregated V2 response to `/logs/findings_details_<deployment_id>_<timestamp>.json`
6. Transform findings to SARIF 2.1.0 format
7. Write SARIF output to specified file (default: `./output/results.sarif`)

### Output

- **SARIF File**: Valid SARIF 2.1.0 format at configured path
- **Debug Logs**: 
  - `/logs/findings_<deployment_id>_<timestamp>.json` (V1 API response)
  - `/logs/findings_details_<deployment_id>_<timestamp>.json` (V2 API responses)
  - `/logs/converter_<timestamp>.log` (Application logs)

## Architecture

### Workflow

```
.env Config → V1 API (findings list) → V2 API (details) → SARIF Transform → Output File
     ↓              ↓                      ↓                    ↓
   Validation    Debug Log              Debug Log           Validation
```

### Key Components

- **`utils.py`**: Configuration loading and logging utilities
- **`models.py`**: Pydantic data models for APIs and SARIF
- **`semgrep_client.py`**: V1 and V2 API clients with error handling
- **`sarif_transformer.py`**: Core transformation logic
- **`sarif_validator.py`**: SARIF validation and output handling
- **`main.py`**: Main workflow orchestration

### Data Mapping

Key field mappings from Semgrep to SARIF:

| Semgrep V2 Field | SARIF Field | Notes |
|------------------|-------------|-------|
| `id` | `ruleId` | Rule identifier |
| `message` | `message.text` | Finding message |
| `filePath` | `physicalLocation.artifactLocation.uri` | File location |
| `line`, `column` | `physicalLocation.region.start*` | Position info |
| `severity` | `level` | HIGH→error, MEDIUM→warning, LOW→note |
| `dataflowTrace` | `threadFlows` | Dataflow to SARIF codeFlows |
| `ruleCweNames` | `taxa` | CWE classifications |
| `ruleOwaspNames` | `taxa` | OWASP classifications |

## Development

### Running Tests

```bash
pytest tests/
```

### Code Formatting

```bash
black src/ tests/
```

### Type Checking

```bash
mypy src/
```

## Troubleshooting

### Common Issues

1. **Authentication Error**: Check API token format and permissions
2. **Deployment Not Found**: Verify deployment slug and ID
3. **Rate Limiting**: Application handles rate limits automatically with exponential backoff
4. **Missing Findings**: Check deployment has findings and user has access

### Debug Information

- Check `/logs/` folder for detailed JSON dumps of API responses
- Application logs include correlation IDs for tracing requests
- SARIF validation errors show specific schema violations

### Log Files

- `findings_<deployment_id>_<timestamp>.json`: Raw V1 API response
- `findings_details_<deployment_id>_<timestamp>.json`: All V2 API responses
- `converter_<timestamp>.log`: Application execution logs

## API Limitations

- **V1 API**: Limited dataflow information, used for findings list
- **V2 API**: Rich dataflow traces but requires individual calls per finding  
- **Rate Limiting**: Automatically handled with exponential backoff
- **Large Datasets**: Processing time scales linearly with finding count

## Security

- API tokens are read from environment variables only
- No credentials are logged or exposed in output
- File paths are sanitized to prevent directory traversal
- HTTPS used for all API communications

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Run linting and type checking
5. Submit a pull request

## License

[Add license information]

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review debug logs in `/logs/` folder  
3. Create an issue with log excerpts and configuration (redacted)