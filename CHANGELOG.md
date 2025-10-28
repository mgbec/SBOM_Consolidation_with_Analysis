# Changelog

All notable changes to the GitHub SBOM Consolidator project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-10-28

### Added
- Initial release of GitHub SBOM Consolidator
- Multi-repository SBOM generation from GitHub repositories
- Support for Node.js, Python, Java, and .NET ecosystems
- SPDX and CycloneDX format export capabilities
- SBOM consolidation with intelligent deduplication
- AWS Bedrock AgentCore integration for AI-powered risk analysis
- Automated security recommendations using foundation models
- Comprehensive logging and error handling system
- CLI interface with multiple commands and options
- Configuration management with environment variable support
- Vulnerability and license information integration
- Extensive test suite with unit and integration tests
- Docker containerization support
- Professional documentation and examples

### Features
- **Multi-Language Support**: JavaScript/Node.js, Python, Java, .NET
- **AI-Powered Analysis**: Risk assessment and security recommendations
- **Standard Formats**: SPDX, CycloneDX, and JSON export
- **Consolidation**: Merge multiple SBOMs with deduplication
- **Source Traceability**: Preserve repository and file source information
- **Extensible Architecture**: Plugin-based parser system
- **Robust Error Handling**: Comprehensive error recovery mechanisms
- **Performance Optimized**: Efficient processing and caching
- **Enterprise Ready**: Professional logging, monitoring, and statistics

### Dependencies
- Python 3.8+
- AWS Bedrock access for AI features
- GitHub personal access token for repository access
- Standard Python packages for SBOM generation and parsing