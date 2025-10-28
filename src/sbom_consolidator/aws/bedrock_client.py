"""
AWS Bedrock client for foundation model access and AI-powered analysis.
"""

import boto3
import json
import logging
from typing import Dict, Any, Optional, List
from botocore.exceptions import ClientError, NoCredentialsError

from ..config import get_config

logger = logging.getLogger(__name__)


class BedrockClient:
    """
    AWS Bedrock client for accessing foundation models and AI capabilities.
    
    This client provides a unified interface for interacting with AWS Bedrock
    foundation models for AI-powered dependency risk analysis and security recommendations.
    """
    
    def __init__(self, region: Optional[str] = None):
        """
        Initialize Bedrock client.
        
        Args:
            region: AWS region for Bedrock services
        """
        self.config = get_config()
        self.region = region or self.config.aws.region
        
        # Initialize Bedrock client
        try:
            self.bedrock_client = boto3.client(
                'bedrock-runtime',
                region_name=self.region
            )
            logger.info(f"Initialized Bedrock client for region: {self.region}")
        except NoCredentialsError:
            logger.error("AWS credentials not found. Please configure AWS credentials.")
            self.bedrock_client = None
        except Exception as e:
            logger.error(f"Failed to initialize Bedrock client: {e}")
            self.bedrock_client = None
    
    def is_available(self) -> bool:
        """
        Check if Bedrock client is available and configured.
        
        Returns:
            True if client is available
        """
        return self.bedrock_client is not None
    
    def invoke_model(
        self, 
        model_id: str, 
        prompt: str, 
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        **kwargs
    ) -> Optional[str]:
        """
        Invoke a Bedrock foundation model with a prompt.
        
        Args:
            model_id: Bedrock model identifier
            prompt: Input prompt for the model
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            **kwargs: Additional model parameters
            
        Returns:
            Model response text or None if failed
        """
        if not self.is_available():
            logger.error("Bedrock client not available")
            return None
        
        # Use config defaults if not specified
        max_tokens = max_tokens or self.config.bedrock.max_tokens
        temperature = temperature or self.config.bedrock.temperature
        
        try:
            # Prepare request body based on model type
            if "anthropic.claude" in model_id:
                body = {
                    "prompt": f"\\n\\nHuman: {prompt}\\n\\nAssistant:",
                    "max_tokens_to_sample": max_tokens,
                    "temperature": temperature,
                    "top_p": kwargs.get("top_p", 0.9),
                    "stop_sequences": kwargs.get("stop_sequences", ["\\n\\nHuman:"])
                }
            elif "amazon.titan" in model_id:
                body = {
                    "inputText": prompt,
                    "textGenerationConfig": {
                        "maxTokenCount": max_tokens,
                        "temperature": temperature,
                        "topP": kwargs.get("top_p", 0.9),
                        "stopSequences": kwargs.get("stop_sequences", [])
                    }
                }
            else:
                # Generic format
                body = {
                    "prompt": prompt,
                    "max_tokens": max_tokens,
                    "temperature": temperature
                }
            
            # Invoke the model
            response = self.bedrock_client.invoke_model(
                modelId=model_id,
                body=json.dumps(body),
                contentType="application/json",
                accept="application/json"
            )
            
            # Parse response
            response_body = json.loads(response['body'].read())
            
            # Extract text based on model type
            if "anthropic.claude" in model_id:
                return response_body.get('completion', '').strip()
            elif "amazon.titan" in model_id:
                results = response_body.get('results', [])
                if results:
                    return results[0].get('outputText', '').strip()
            else:
                # Try common response fields
                for field in ['text', 'completion', 'output', 'response']:
                    if field in response_body:
                        return response_body[field].strip()
            
            logger.warning(f"Could not extract text from model response: {response_body}")
            return None
            
        except ClientError as e:
            logger.error(f"AWS Bedrock API error: {e}")
            return None
        except Exception as e:
            logger.error(f"Error invoking Bedrock model {model_id}: {e}")
            return None
    
    def analyze_dependency_risk(self, dependency_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Analyze dependency risk using AI models.
        
        Args:
            dependency_data: Dictionary containing dependency information
            
        Returns:
            Risk analysis results or None if failed
        """
        if not self.config.bedrock.enable_risk_analysis:
            logger.info("AI risk analysis disabled in configuration")
            return None
        
        model_id = self.config.bedrock.risk_analysis_model
        
        # Create prompt for risk analysis
        prompt = self._create_risk_analysis_prompt(dependency_data)
        
        # Invoke model
        response = self.invoke_model(model_id, prompt)
        
        if response:
            try:
                # Parse JSON response
                risk_analysis = json.loads(response)
                return risk_analysis
            except json.JSONDecodeError:
                # If not JSON, try to extract structured information
                return self._parse_risk_analysis_text(response)
        
        return None
    
    def generate_security_recommendations(
        self, 
        sbom_data: Dict[str, Any], 
        risk_analysis: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Generate security recommendations using AI models.
        
        Args:
            sbom_data: SBOM data for analysis
            risk_analysis: Optional risk analysis results
            
        Returns:
            Security recommendations or None if failed
        """
        if not self.config.bedrock.enable_security_recommendations:
            logger.info("AI security recommendations disabled in configuration")
            return None
        
        model_id = self.config.bedrock.security_advisor_model
        
        # Create prompt for security recommendations
        prompt = self._create_security_recommendations_prompt(sbom_data, risk_analysis)
        
        # Invoke model
        response = self.invoke_model(model_id, prompt)
        
        if response:
            try:
                # Parse JSON response
                recommendations = json.loads(response)
                return recommendations
            except json.JSONDecodeError:
                # If not JSON, try to extract structured information
                return self._parse_security_recommendations_text(response)
        
        return None
    
    def _create_risk_analysis_prompt(self, dependency_data: Dict[str, Any]) -> str:
        """Create prompt for dependency risk analysis."""
        dependencies = dependency_data.get('dependencies', [])
        repository_info = dependency_data.get('repository', {})
        
        prompt = f"""
Analyze the security risk of the following software dependencies and provide a structured risk assessment.

Repository Information:
- Name: {repository_info.get('name', 'Unknown')}
- Language: {repository_info.get('language', 'Unknown')}
- Description: {repository_info.get('description', 'N/A')}

Dependencies to analyze ({len(dependencies)} total):
"""
        
        # Add dependency information
        for i, dep in enumerate(dependencies[:20]):  # Limit to first 20 for prompt size
            prompt += f"""
{i+1}. {dep.get('name', 'Unknown')}
   - Version: {dep.get('version', 'Unknown')}
   - Package Manager: {dep.get('package_manager', 'Unknown')}
   - Type: {dep.get('dependency_type', 'Unknown')}
   - Vulnerabilities: {len(dep.get('vulnerabilities', []))}
"""
        
        if len(dependencies) > 20:
            prompt += f"... and {len(dependencies) - 20} more dependencies\n"
        
        prompt += """
Please provide a risk analysis in the following JSON format:
{
  "overall_risk_score": <float 0-10>,
  "overall_risk_level": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "risk_factors": [
    "list of identified risk factors"
  ],
  "component_risks": [
    {
      "component_name": "package_name",
      "risk_score": <float 0-10>,
      "risk_level": "<LOW|MEDIUM|HIGH|CRITICAL>",
      "risk_factors": ["specific risk factors for this component"],
      "confidence_score": <float 0-1>
    }
  ],
  "transitive_risks": [
    {
      "source_component": "parent_package",
      "target_component": "dependency_package", 
      "risk_score": <float 0-10>,
      "description": "description of the transitive risk"
    }
  ],
  "confidence_score": <float 0-1>
}

Focus on:
1. Known vulnerabilities and security issues
2. Package age and maintenance status
3. Dependency chain complexity
4. License compatibility issues
5. Package popularity and community trust
6. Transitive dependency risks
"""
        
        return prompt
    
    def _create_security_recommendations_prompt(
        self, 
        sbom_data: Dict[str, Any], 
        risk_analysis: Optional[Dict[str, Any]] = None
    ) -> str:
        """Create prompt for security recommendations."""
        dependencies = sbom_data.get('dependencies', [])
        repository_info = sbom_data.get('repository', {})
        
        prompt = f"""
Generate security recommendations for the following software project based on its dependencies and risk analysis.

Project Information:
- Name: {repository_info.get('name', 'Unknown')}
- Language: {repository_info.get('language', 'Unknown')}
- Total Dependencies: {len(dependencies)}
"""
        
        if risk_analysis:
            prompt += f"""
Risk Analysis Summary:
- Overall Risk Score: {risk_analysis.get('overall_risk_score', 'N/A')}
- Overall Risk Level: {risk_analysis.get('overall_risk_level', 'N/A')}
- High Risk Components: {len([c for c in risk_analysis.get('component_risks', []) if c.get('risk_level') in ['HIGH', 'CRITICAL']])}
"""
        
        # Add high-risk dependencies
        high_risk_deps = []
        if risk_analysis:
            for comp_risk in risk_analysis.get('component_risks', []):
                if comp_risk.get('risk_level') in ['HIGH', 'CRITICAL']:
                    high_risk_deps.append(comp_risk)
        
        if high_risk_deps:
            prompt += "\nHigh Risk Dependencies:\n"
            for dep in high_risk_deps[:10]:  # Limit to top 10
                prompt += f"- {dep.get('component_name')}: {dep.get('risk_level')} ({dep.get('risk_score')}/10)\n"
        
        prompt += """
Please provide security recommendations in the following JSON format:
{
  "recommendations": [
    {
      "recommendation_id": "unique_id",
      "priority": "<LOW|MEDIUM|HIGH|CRITICAL>",
      "title": "Brief recommendation title",
      "description": "Detailed description of the recommendation",
      "affected_components": ["list of affected package names"],
      "remediation_steps": [
        "Step 1: Specific action to take",
        "Step 2: Next action",
        "..."
      ],
      "estimated_effort": "<LOW|MEDIUM|HIGH>",
      "risk_reduction": <float 0-10>
    }
  ],
  "alternative_suggestions": [
    {
      "original_component": "risky_package_name",
      "alternative_component": "safer_alternative_name",
      "reason": "Why this alternative is better",
      "risk_reduction": <float 0-10>,
      "compatibility_notes": "Migration considerations",
      "migration_effort": "<LOW|MEDIUM|HIGH>"
    }
  ],
  "contextual_guidance": [
    "General security best practices for this project type",
    "Specific recommendations based on the technology stack",
    "..."
  ]
}

Focus on:
1. Updating vulnerable dependencies
2. Replacing high-risk packages with safer alternatives
3. Implementing security monitoring
4. Dependency management best practices
5. License compliance issues
6. Supply chain security measures
"""
        
        return prompt
    
    def _parse_risk_analysis_text(self, text: str) -> Dict[str, Any]:
        """Parse risk analysis from unstructured text."""
        # Basic parsing fallback if JSON parsing fails
        lines = text.split('\n')
        
        risk_analysis = {
            "overall_risk_score": 5.0,
            "overall_risk_level": "MEDIUM",
            "risk_factors": [],
            "component_risks": [],
            "transitive_risks": [],
            "confidence_score": 0.5,
            "raw_analysis": text
        }
        
        # Try to extract key information
        for line in lines:
            line = line.strip().lower()
            if 'high risk' in line or 'critical' in line:
                risk_analysis["overall_risk_level"] = "HIGH"
                risk_analysis["overall_risk_score"] = 7.0
            elif 'low risk' in line:
                risk_analysis["overall_risk_level"] = "LOW"
                risk_analysis["overall_risk_score"] = 3.0
        
        return risk_analysis
    
    def _parse_security_recommendations_text(self, text: str) -> Dict[str, Any]:
        """Parse security recommendations from unstructured text."""
        # Basic parsing fallback if JSON parsing fails
        recommendations = {
            "recommendations": [],
            "alternative_suggestions": [],
            "contextual_guidance": [text],
            "raw_recommendations": text
        }
        
        # Try to extract recommendations
        lines = text.split('\n')
        current_recommendation = None
        
        for line in lines:
            line = line.strip()
            if line.startswith(('1.', '2.', '3.', '-', '*')):
                if current_recommendation:
                    recommendations["recommendations"].append(current_recommendation)
                
                current_recommendation = {
                    "recommendation_id": f"rec_{len(recommendations['recommendations']) + 1}",
                    "priority": "MEDIUM",
                    "title": line,
                    "description": line,
                    "affected_components": [],
                    "remediation_steps": [line],
                    "estimated_effort": "MEDIUM",
                    "risk_reduction": 5.0
                }
        
        if current_recommendation:
            recommendations["recommendations"].append(current_recommendation)
        
        return recommendations
    
    def test_connection(self) -> bool:
        """
        Test connection to AWS Bedrock.
        
        Returns:
            True if connection is successful
        """
        if not self.is_available():
            return False
        
        try:
            # Try a simple model invocation
            test_prompt = "Hello, this is a test. Please respond with 'OK'."
            response = self.invoke_model(
                self.config.bedrock.risk_analysis_model,
                test_prompt,
                max_tokens=10
            )
            
            if response:
                logger.info("Bedrock connection test successful")
                return True
            else:
                logger.warning("Bedrock connection test failed - no response")
                return False
                
        except Exception as e:
            logger.error(f"Bedrock connection test failed: {e}")
            return False