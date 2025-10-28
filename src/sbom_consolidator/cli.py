"""
Command-line interface for the GitHub SBOM Consolidator.
"""

import click
import logging
import sys
from typing import List, Optional, Dict, Any
from pathlib import Path

from . import __version__
from .config import get_config_manager
from .orchestrator import OrchestrationManager


@click.group()
@click.version_option(version=__version__)
@click.option(
    '--config', '-c',
    type=click.Path(exists=True, path_type=Path),
    help='Path to configuration file'
)
@click.option(
    '--verbose', '-v',
    count=True,
    help='Increase verbosity (use -v, -vv, or -vvv)'
)
@click.pass_context
def cli(ctx: click.Context, config: Optional[Path], verbose: int) -> None:
    """
    GitHub SBOM Consolidator - Generate and consolidate SBOMs from GitHub repositories.
    
    This tool provides AI-powered dependency analysis and SBOM generation
    with support for multiple programming languages and output formats.
    """
    # Ensure context object exists
    ctx.ensure_object(dict)
    
    # Set up logging based on verbosity
    setup_logging(verbose)
    
    # Store global options in context
    ctx.obj['config_file'] = config
    ctx.obj['verbose'] = verbose
    
    # Display banner
    if verbose > 0:
        click.echo(f"GitHub SBOM Consolidator v{__version__}")


@cli.command()
@click.option(
    '--repos', '-r',
    multiple=True,
    required=True,
    help='GitHub repository URLs to process'
)
@click.option(
    '--output', '-o',
    type=click.Path(path_type=Path),
    help='Output directory for generated SBOMs'
)
@click.option(
    '--format', '-f',
    type=click.Choice(['spdx', 'cyclonedx', 'json'], case_sensitive=False),
    multiple=True,
    help='Output format(s) for SBOMs'
)
@click.option(
    '--consolidate/--no-consolidate',
    default=True,
    help='Generate consolidated SBOM from all repositories'
)
@click.option(
    '--include-dev/--no-include-dev',
    default=False,
    help='Include development dependencies'
)
@click.option(
    '--vulnerability-check/--no-vulnerability-check',
    default=True,
    help='Include vulnerability information'
)
@click.option(
    '--license-detection/--no-license-detection',
    default=True,
    help='Include license information'
)
@click.option(
    '--ai-analysis/--no-ai-analysis',
    default=True,
    help='Enable AI-powered risk analysis and recommendations'
)
@click.option(
    '--branch', '-b',
    help='Git branch to analyze (defaults to repository default branch)'
)
@click.option(
    '--depth',
    type=int,
    default=1,
    help='Git clone depth (1 for shallow clone)'
)
@click.option(
    '--include-timestamp/--no-include-timestamp',
    default=True,
    help='Include timestamp in output filenames'
)
@click.option(
    '--cleanup/--no-cleanup',
    default=True,
    help='Clean up temporary files after processing'
)
@click.pass_context
def generate(
    ctx: click.Context,
    repos: List[str],
    output: Optional[Path],
    format: List[str],
    consolidate: bool,
    include_dev: bool,
    vulnerability_check: bool,
    license_detection: bool,
    ai_analysis: bool,
    branch: Optional[str],
    depth: int,
    include_timestamp: bool,
    cleanup: bool
) -> None:
    """
    Generate SBOMs from GitHub repositories.
    
    This command clones the specified GitHub repositories, scans them for
    dependencies, generates individual SBOMs, and optionally consolidates
    them into a unified report with AI-powered analysis.
    
    Examples:
    
        # Process single repository
        sbom-consolidator generate -r https://github.com/user/repo
        
        # Process multiple repositories with custom output
        sbom-consolidator generate -r https://github.com/user/repo1 -r https://github.com/user/repo2 -o ./output
        
        # Generate only SPDX format without consolidation
        sbom-consolidator generate -r https://github.com/user/repo -f spdx --no-consolidate
        
        # Include development dependencies with AI analysis
        sbom-consolidator generate -r https://github.com/user/repo --include-dev --ai-analysis
    """
    try:
        # Validate inputs
        validate_inputs(repos, output, format)
        
        # Initialize configuration
        config_manager = get_config_manager(ctx.obj.get('config_file'))
        config = config_manager.get_config()
        
        # Override configuration with CLI options
        cli_overrides = create_cli_overrides(
            output, format, include_dev, vulnerability_check, 
            license_detection, ai_analysis, include_timestamp
        )
        
        # Initialize orchestrator
        orchestrator = OrchestrationManager(config, cli_overrides)
        
        # Process repositories
        results = orchestrator.process_repositories(
            repo_urls=list(repos),
            branch=branch,
            depth=depth,
            consolidate=consolidate,
            cleanup=cleanup
        )
        
        # Display results
        display_results(results, ctx.obj.get('verbose', 0))
        
        # Exit with appropriate code
        if results.get('errors'):
            sys.exit(1)
        else:
            sys.exit(0)
            
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        if ctx.obj.get('verbose', 0) > 1:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.option(
    '--format', '-f',
    type=click.Choice(['table', 'json', 'yaml'], case_sensitive=False),
    default='table',
    help='Output format for configuration display'
)
@click.pass_context
def config(ctx: click.Context, format: str) -> None:
    """
    Display current configuration settings.
    
    Shows the current configuration including defaults, file settings,
    and environment variable overrides.
    """
    try:
        config_manager = get_config_manager(ctx.obj.get('config_file'))
        config = config_manager.get_config()
        
        if format == 'json':
            import json
            config_dict = {
                'github': config.github.__dict__,
                'output': config.output.__dict__,
                'scanning': config.scanning.__dict__,
                'logging': config.logging.__dict__,
                'vulnerability': config.vulnerability.__dict__,
                'consolidation': config.consolidation.__dict__,
                'aws': config.aws.__dict__,
                'bedrock': config.bedrock.__dict__
            }
            click.echo(json.dumps(config_dict, indent=2, default=str))
        elif format == 'yaml':
            import yaml
            config_dict = {
                'github': config.github.__dict__,
                'output': config.output.__dict__,
                'scanning': config.scanning.__dict__,
                'logging': config.logging.__dict__,
                'vulnerability': config.vulnerability.__dict__,
                'consolidation': config.consolidation.__dict__,
                'aws': config.aws.__dict__,
                'bedrock': config.bedrock.__dict__
            }
            click.echo(yaml.dump(config_dict, default_flow_style=False))
        else:
            display_config_table(config)
            
    except Exception as e:
        click.echo(f"Error displaying configuration: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.pass_context
def test_aws(ctx: click.Context) -> None:
    """
    Test AWS Bedrock connectivity and configuration.
    
    Verifies that AWS credentials are configured correctly and that
    the Bedrock service is accessible for AI-powered analysis.
    """
    try:
        from .aws import BedrockClient
        
        click.echo("Testing AWS Bedrock connectivity...")
        
        bedrock_client = BedrockClient()
        
        if not bedrock_client.is_available():
            click.echo("❌ AWS Bedrock client not available", err=True)
            click.echo("Please check your AWS credentials and configuration", err=True)
            sys.exit(1)
        
        # Test connection
        if bedrock_client.test_connection():
            click.echo("✅ AWS Bedrock connection successful")
            click.echo(f"Region: {bedrock_client.region}")
        else:
            click.echo("❌ AWS Bedrock connection failed", err=True)
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"Error testing AWS connection: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    '--format', '-f',
    type=click.Choice(['table', 'json'], case_sensitive=False),
    default='table',
    help='Output format for statistics'
)
@click.pass_context
def stats(ctx: click.Context, format: str) -> None:
    """
    Display usage statistics and metrics.
    
    Shows statistics about previous SBOM generation runs,
    including performance metrics and error rates.
    """
    # This would be implemented to show cached statistics
    click.echo("Statistics feature coming soon!")


def setup_logging(verbose: int) -> None:
    """Set up logging based on verbosity level."""
    if verbose == 0:
        level = logging.WARNING
    elif verbose == 1:
        level = logging.INFO
    elif verbose == 2:
        level = logging.DEBUG
    else:
        level = logging.DEBUG
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Reduce noise from third-party libraries
    if verbose < 3:
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('requests').setLevel(logging.WARNING)
        logging.getLogger('git').setLevel(logging.WARNING)


def validate_inputs(repos: List[str], output: Optional[Path], formats: List[str]) -> None:
    """Validate CLI inputs."""
    if not repos:
        raise click.BadParameter("At least one repository URL is required")
    
    # Validate repository URLs
    for repo in repos:
        if not (repo.startswith('https://github.com/') or repo.startswith('git@github.com:')):
            raise click.BadParameter(f"Invalid GitHub repository URL: {repo}")
    
    # Validate output directory
    if output and output.exists() and not output.is_dir():
        raise click.BadParameter(f"Output path exists but is not a directory: {output}")
    
    # Validate formats
    valid_formats = {'spdx', 'cyclonedx', 'json'}
    for fmt in formats:
        if fmt.lower() not in valid_formats:
            raise click.BadParameter(f"Invalid format: {fmt}")


def create_cli_overrides(
    output: Optional[Path],
    formats: List[str],
    include_dev: bool,
    vulnerability_check: bool,
    license_detection: bool,
    ai_analysis: bool,
    include_timestamp: bool
) -> Dict[str, Any]:
    """Create configuration overrides from CLI options."""
    overrides = {}
    
    if output:
        overrides['output_directory'] = str(output)
    
    if formats:
        overrides['output_formats'] = list(formats)
    
    overrides.update({
        'include_dev_dependencies': include_dev,
        'vulnerability_check': vulnerability_check,
        'license_detection': license_detection,
        'ai_analysis': ai_analysis,
        'include_timestamp': include_timestamp
    })
    
    return overrides


def display_results(results: Dict[str, Any], verbose: int) -> None:
    """Display processing results."""
    click.echo("\n" + "="*60)
    click.echo("SBOM GENERATION RESULTS")
    click.echo("="*60)
    
    # Summary
    repos_processed = results.get('repositories_processed', 0)
    sboms_generated = results.get('sboms_generated', 0)
    consolidated_sbom = results.get('consolidated_sbom')
    errors = results.get('errors', [])
    
    click.echo(f"Repositories processed: {repos_processed}")
    click.echo(f"SBOMs generated: {sboms_generated}")
    
    if consolidated_sbom:
        click.echo(f"Consolidated SBOM: ✅ Generated")
        if verbose > 0:
            click.echo(f"  - Components: {consolidated_sbom.get('component_count', 'N/A')}")
            click.echo(f"  - Vulnerabilities: {consolidated_sbom.get('vulnerability_count', 'N/A')}")
    
    # Errors
    if errors:
        click.echo(f"\nErrors encountered: {len(errors)}")
        if verbose > 0:
            for error in errors[:5]:  # Show first 5 errors
                click.echo(f"  - {error}")
            if len(errors) > 5:
                click.echo(f"  ... and {len(errors) - 5} more errors")
    else:
        click.echo("Errors: None")
    
    # Statistics
    statistics = results.get('statistics', {})
    if statistics and verbose > 0:
        click.echo(f"\nProcessing Statistics:")
        click.echo(f"  - Total dependencies found: {statistics.get('total_dependencies', 'N/A')}")
        click.echo(f"  - Unique licenses: {statistics.get('unique_licenses', 'N/A')}")
        click.echo(f"  - Package managers: {statistics.get('package_managers', 'N/A')}")
    
    # Output files
    output_files = results.get('output_files', [])
    if output_files:
        click.echo(f"\nOutput files generated:")
        for file_path in output_files:
            click.echo(f"  - {file_path}")
    
    click.echo("="*60)


def display_config_table(config) -> None:
    """Display configuration in table format."""
    click.echo("\nCurrent Configuration:")
    click.echo("-" * 50)
    
    sections = [
        ("GitHub", config.github),
        ("Output", config.output),
        ("Scanning", config.scanning),
        ("Logging", config.logging),
        ("Vulnerability", config.vulnerability),
        ("Consolidation", config.consolidation),
        ("AWS", config.aws),
        ("Bedrock", config.bedrock)
    ]
    
    for section_name, section_config in sections:
        click.echo(f"\n[{section_name}]")
        for key, value in section_config.__dict__.items():
            if key == 'access_token' and value:
                value = '*' * 8  # Hide sensitive values
            elif key in ['access_key_id', 'secret_access_key'] and value:
                value = '*' * 8
            click.echo(f"  {key}: {value}")


def main() -> None:
    """Main entry point for the CLI."""
    cli()


if __name__ == '__main__':
    main()