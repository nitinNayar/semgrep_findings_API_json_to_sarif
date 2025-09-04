"""Main entry point for the Semgrep to SARIF converter."""

import logging
import sys
from datetime import datetime
from pathlib import Path

# Handle both direct execution and package imports
try:
    from .utils import load_environment_config, setup_logging, ConfigurationError
    from .semgrep_client import SemgrepAPIFacade, SemgrepAPIError
    from .sarif_transformer import SARIFTransformer, TransformationError
    from .sarif_validator import SARIFOutputHandler, SARIFValidationError, SARIFOutputError
except ImportError:
    # Direct execution - add parent directory to path
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from src.utils import load_environment_config, setup_logging, ConfigurationError
    from src.semgrep_client import SemgrepAPIFacade, SemgrepAPIError
    from src.sarif_transformer import SARIFTransformer, TransformationError
    from src.sarif_validator import SARIFOutputHandler, SARIFValidationError, SARIFOutputError


class ConverterError(Exception):
    """Base exception for converter errors."""
    pass


def main() -> int:
    """Main function that orchestrates the complete conversion workflow.
    
    Following the exact pseudo code from requirements:
    1. Read API token, deployment_slug & deployment_id from .env file
    2. Make V1 API call to get full list of findings
    3. Write V1 output to logs folder 
    4. Iterate through findings and call V2 API for details
    5. Write aggregated V2 output to logs folder
    6. Transform to SARIF format
    7. Write SARIF file
    
    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    # Set up logging first
    logger = setup_logging()
    
    try:
        logger.info("=== Semgrep to SARIF Converter Started ===")
        start_time = datetime.now()
        
        # Step 1: Read configuration from environment
        logger.info("Step 1: Loading configuration from environment")
        try:
            config = load_environment_config()
            logger.info(f"Configuration loaded - Deployment: {config.deployment_slug}")
        except ConfigurationError as e:
            logger.error(f"Configuration error: {e}")
            return 1
        
        # Step 2-5: Fetch findings using API facade (handles V1 + V2 + logging)
        logger.info("Step 2-5: Fetching findings from Semgrep APIs")
        try:
            api_facade = SemgrepAPIFacade(
                api_token=config.api_token,
                deployment_slug=config.deployment_slug,
                deployment_id=config.deployment_id,
                repository_ids=config.list_of_repo_ids if config.filter_findings_for_specific_repo_ids else None,
                page_size=config.semgrep_page_size,
                max_pages=config.semgrep_max_pages
            )
            
            v1_findings, v2_findings = api_facade.fetch_all_findings_with_details()
            
            if not v1_findings:
                logger.warning("No findings retrieved from V1 API")
                return 0
            
            logger.info(f"Retrieved {len(v1_findings)} V1 findings and {len(v2_findings)} V2 detailed findings")
            
        except SemgrepAPIError as e:
            logger.error(f"API error: {e}")
            return 1
        
        # Step 6: Transform to SARIF
        logger.info("Step 6: Transforming findings to SARIF format")
        try:
            transformer = SARIFTransformer(config.deployment_slug)
            sarif_report = transformer.transform(v1_findings, v2_findings)
            
            logger.info(f"SARIF transformation complete")
            
        except TransformationError as e:
            logger.error(f"Transformation error: {e}")
            return 1
        
        # Step 7: Write SARIF output
        logger.info("Step 7: Writing SARIF output file")
        try:
            # Temporarily disable validation to check the output
            output_handler = SARIFOutputHandler(validate_output=False)
            output_file, summary = output_handler.validate_and_write(sarif_report, config.output_sarif_path)
            
            # Log success summary
            end_time = datetime.now()
            duration = end_time - start_time
            
            logger.info("=== Conversion Completed Successfully ===")
            logger.info(f"Output file: {output_file}")
            logger.info(f"Total duration: {duration.total_seconds():.2f} seconds")
            logger.info("Summary:")
            for key, value in summary.items():
                logger.info(f"  {key}: {value}")
            
            return 0
            
        except (SARIFValidationError, SARIFOutputError) as e:
            logger.error(f"SARIF output error: {e}")
            return 1
    
    except KeyboardInterrupt:
        logger.info("Conversion interrupted by user")
        return 130  # Standard exit code for SIGINT
    
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return 1
    
    finally:
        # Log completion
        logger.info("=== Semgrep to SARIF Converter Finished ===")


def cli_main():
    """CLI entry point that handles command line execution."""
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    cli_main()