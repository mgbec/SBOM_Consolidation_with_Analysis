# GitHub SBOM Consolidator

A Python application that automates the creation and consolidation of Software Bill of Materials (SBOMs) from multiple GitHub repositories.

## Features

- **Multi-Repository Support**: Process multiple GitHub repositories in a single run
- **Multiple Language Support**: Supports Node.js, Python, Java, and .NET projects
- **Standard SBOM Formats**: Generates SBOMs in SPDX and CycloneDX formats
- **Consolidation**: Merges multiple SBOMs into unified reports with deduplication
- **Security Integration**: Includes vulnerability and license information
- **AI-Powered Risk Analysis**: Uses AWS Bedrock AgentCore for intelligent dependency risk assessment
- **Automated Security Recommendations**: Generates AI-driven security guidance and remediation plans
- **Extensible Architecture**: Plugin-based system for adding new language parsers

## Installation

### From PyPI (when available)
```bash
pip install github-sbom-consolidator
```

### From Source
```bash
git clone <repository-url>
cd github-sbom-consolidator
pip install -e .
```

## Quick Start

1. Set your GitHub personal access token:
```bash
export GITHUB_TOKEN=your_github_token_here
```

2. Run the consolidator:
```bash
sbom-consolidator --repos https://github.com/user/repo1 https://github.com/user/repo2
```

## Configuration

The tool can be configured via YAML configuration files or environment variables. See `config/default.yaml` for all available options.

### Environment Variables

- `GITHUB_TOKEN`: GitHub personal access token (required)
- `AWS_ACCESS_KEY_ID`: AWS access key for Bedrock services (required for AI features)
- `AWS_SECRET_ACCESS_KEY`: AWS secret key for Bedrock services (required for AI features)
- `AWS_REGION`: AWS region for Bedrock services (default: us-east-1)
- `SBOM_OUTPUT_DIR`: Override default output directory
- `LOG_LEVEL`: Override logging level

## Supported Languages

- **JavaScript/Node.js**: package.json, package-lock.json
- **Python**: requirements.txt, setup.py, pyproject.toml
- **Java**: pom.xml (Maven)
- **.NET**: packages.config, *.csproj

## Output Formats

- **SPDX**: Industry standard SBOM format
- **CycloneDX**: OWASP SBOM standard
- **JSON**: Custom JSON format for programmatic access

## Development

### Setup Development Environment
```bash
git clone <repository-url>
cd github-sbom-consolidator
pip install -e ".[dev]"
```

### Run Tests
```bash
pytest
```

### Code Formatting
```bash
black src/
flake8 src/
mypy src/
```

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please read CONTRIBUTING.md for guidelines.