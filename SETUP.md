# Setup Instructions

## Virtual Environment Setup

### 1. Activate the Virtual Environment

```bash
# Activate virtual environment (do this every time you work on the project)
source venv/bin/activate
```

You'll see `(venv)` in your terminal prompt when the virtual environment is active.

### 2. Verify Installation

```bash
# Check that dependencies are installed
pip list

# Run tests to verify everything works
python -m pytest tests/ -v
```

### 3. Configure Environment Variables

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env with your actual Semgrep credentials
# Required variables:
# - SEMGREP_API_TOKEN=sg_your_actual_token_here
# - SEMGREP_DEPLOYMENT_SLUG=your-deployment-slug
# - SEMGREP_DEPLOYMENT_ID=your-deployment-id
```

### 4. Run the Converter

```bash
# With virtual environment activated
python src/main.py
```

### 5. Deactivate Virtual Environment

```bash
# When you're done working
deactivate
```

## Development Commands

```bash
# Run tests
python -m pytest tests/ -v

# Run tests with coverage
python -m pytest tests/ --cov=src

# Format code
black src/ tests/

# Type checking
mypy src/

# Run a specific test file
python -m pytest tests/test_utils.py -v
```

## Project Structure

```
semgrep-sarif-converter/
├── venv/                   # Virtual environment (created)
├── src/                    # Source code
├── tests/                  # Unit tests
├── logs/                   # Debug logs (created at runtime)
├── output/                 # SARIF output (created at runtime)
├── .env                    # Your configuration (create from .env.example)
├── requirements.txt        # Dependencies
└── README.md              # Usage documentation
```

## Notes

- Always activate the virtual environment before working with the project
- The `.env` file is ignored by git for security
- All dependencies are isolated within the virtual environment
- Debug logs and intermediate JSON files are saved in the `logs/` directory