"""
GitHub API client with authentication and rate limiting support.
"""

import requests
import time
import logging
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse
from dataclasses import dataclass
from datetime import datetime, timedelta
import json

from ..models import Repository
from ..config import get_config

logger = logging.getLogger(__name__)


@dataclass
class RateLimitInfo:
    """GitHub API rate limit information."""
    limit: int
    remaining: int
    reset_time: datetime
    used: int


class GitHubAPIError(Exception):
    """Custom exception for GitHub API errors."""
    
    def __init__(self, message: str, status_code: Optional[int] = None, response_data: Optional[Dict] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data


class GitHubClient:
    """
    GitHub API client with authentication, rate limiting, and retry logic.
    
    This client handles GitHub API interactions including repository information
    retrieval, authentication, rate limiting, and error handling.
    """
    
    def __init__(self, access_token: Optional[str] = None, base_url: Optional[str] = None):
        """
        Initialize GitHub API client.
        
        Args:
            access_token: GitHub personal access token
            base_url: GitHub API base URL
        """
        config = get_config()
        
        self.access_token = access_token or config.github.access_token
        self.base_url = base_url or config.github.api_base_url
        self.timeout = config.github.timeout
        self.max_retries = config.github.max_retries
        
        self.session = requests.Session()
        self._setup_session()
        
        self._rate_limit_info: Optional[RateLimitInfo] = None
        self._last_rate_limit_check = datetime.now()
    
    def _setup_session(self) -> None:
        """Set up the requests session with headers and authentication."""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "github-sbom-consolidator/1.0"
        }
        
        if self.access_token:
            headers["Authorization"] = f"token {self.access_token}"
        
        self.session.headers.update(headers)
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """
        Make a request to the GitHub API with retry logic and rate limiting.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (without base URL)
            **kwargs: Additional arguments for requests
            
        Returns:
            Response object
            
        Raises:
            GitHubAPIError: If the request fails after retries
        """
        url = f"{self.base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        
        for attempt in range(self.max_retries + 1):
            try:
                # Check rate limits before making request
                self._check_rate_limits()
                
                # Make the request
                response = self.session.request(
                    method=method,
                    url=url,
                    timeout=self.timeout,
                    **kwargs
                )
                
                # Update rate limit information
                self._update_rate_limit_info(response)
                
                # Handle rate limiting
                if response.status_code == 403 and "rate limit" in response.text.lower():
                    if attempt < self.max_retries:
                        wait_time = self._calculate_rate_limit_wait()
                        logger.warning(f"Rate limited. Waiting {wait_time} seconds before retry {attempt + 1}")
                        time.sleep(wait_time)
                        continue
                    else:
                        raise GitHubAPIError(
                            "Rate limit exceeded and max retries reached",
                            status_code=response.status_code,
                            response_data=response.json() if response.content else None
                        )
                
                # Handle other HTTP errors
                if not response.ok:
                    error_data = None
                    try:
                        error_data = response.json()
                    except json.JSONDecodeError:
                        pass
                    
                    error_message = f"GitHub API request failed: {response.status_code}"
                    if error_data and "message" in error_data:
                        error_message += f" - {error_data['message']}"
                    
                    if attempt < self.max_retries and response.status_code >= 500:
                        # Retry on server errors
                        wait_time = 2 ** attempt  # Exponential backoff
                        logger.warning(f"Server error {response.status_code}. Retrying in {wait_time} seconds")
                        time.sleep(wait_time)
                        continue
                    
                    raise GitHubAPIError(
                        error_message,
                        status_code=response.status_code,
                        response_data=error_data
                    )
                
                return response
                
            except requests.exceptions.RequestException as e:
                if attempt < self.max_retries:
                    wait_time = 2 ** attempt
                    logger.warning(f"Request failed: {e}. Retrying in {wait_time} seconds")
                    time.sleep(wait_time)
                    continue
                else:
                    raise GitHubAPIError(f"Request failed after {self.max_retries} retries: {e}")
        
        raise GitHubAPIError("Unexpected error in request retry logic")
    
    def _update_rate_limit_info(self, response: requests.Response) -> None:
        """
        Update rate limit information from response headers.
        
        Args:
            response: HTTP response object
        """
        headers = response.headers
        
        if "X-RateLimit-Limit" in headers:
            self._rate_limit_info = RateLimitInfo(
                limit=int(headers["X-RateLimit-Limit"]),
                remaining=int(headers.get("X-RateLimit-Remaining", 0)),
                reset_time=datetime.fromtimestamp(int(headers.get("X-RateLimit-Reset", 0))),
                used=int(headers.get("X-RateLimit-Used", 0))
            )
            self._last_rate_limit_check = datetime.now()
    
    def _check_rate_limits(self) -> None:
        """Check if we need to wait due to rate limits."""
        if not self._rate_limit_info:
            return
        
        # If we have very few requests remaining, wait until reset
        if self._rate_limit_info.remaining < 10:
            now = datetime.now()
            if now < self._rate_limit_info.reset_time:
                wait_time = (self._rate_limit_info.reset_time - now).total_seconds() + 1
                logger.info(f"Rate limit nearly exhausted. Waiting {wait_time} seconds until reset")
                time.sleep(wait_time)
    
    def _calculate_rate_limit_wait(self) -> int:
        """
        Calculate how long to wait when rate limited.
        
        Returns:
            Wait time in seconds
        """
        if self._rate_limit_info and self._rate_limit_info.reset_time:
            now = datetime.now()
            if now < self._rate_limit_info.reset_time:
                return int((self._rate_limit_info.reset_time - now).total_seconds()) + 1
        
        # Default wait time if we can't determine reset time
        return 60
    
    def get_rate_limit_info(self) -> Optional[RateLimitInfo]:
        """
        Get current rate limit information.
        
        Returns:
            Rate limit information or None if not available
        """
        return self._rate_limit_info
    
    def authenticate(self) -> bool:
        """
        Test authentication with GitHub API.
        
        Returns:
            True if authentication is successful
            
        Raises:
            GitHubAPIError: If authentication fails
        """
        try:
            response = self._make_request("GET", "/user")
            user_data = response.json()
            logger.info(f"Successfully authenticated as GitHub user: {user_data.get('login', 'unknown')}")
            return True
        except GitHubAPIError as e:
            if e.status_code == 401:
                logger.error("GitHub authentication failed: Invalid or missing access token")
            else:
                logger.error(f"GitHub authentication failed: {e}")
            raise
    
    def get_repository_info(self, repo_url: str) -> Dict[str, Any]:
        """
        Get repository information from GitHub API.
        
        Args:
            repo_url: GitHub repository URL
            
        Returns:
            Repository information dictionary
            
        Raises:
            GitHubAPIError: If repository information cannot be retrieved
        """
        owner, repo_name = self._parse_repo_url(repo_url)
        endpoint = f"/repos/{owner}/{repo_name}"
        
        try:
            response = self._make_request("GET", endpoint)
            repo_data = response.json()
            
            logger.info(f"Retrieved information for repository: {owner}/{repo_name}")
            
            return {
                "name": repo_data["name"],
                "full_name": repo_data["full_name"],
                "owner": repo_data["owner"]["login"],
                "description": repo_data.get("description"),
                "language": repo_data.get("language"),
                "stars": repo_data.get("stargazers_count", 0),
                "forks": repo_data.get("forks_count", 0),
                "last_updated": repo_data.get("updated_at"),
                "default_branch": repo_data.get("default_branch", "main"),
                "clone_url": repo_data["clone_url"],
                "ssh_url": repo_data["ssh_url"],
                "html_url": repo_data["html_url"],
                "private": repo_data.get("private", False),
                "archived": repo_data.get("archived", False),
                "disabled": repo_data.get("disabled", False),
                "topics": repo_data.get("topics", []),
                "license": repo_data.get("license", {}).get("name") if repo_data.get("license") else None
            }
            
        except GitHubAPIError as e:
            if e.status_code == 404:
                raise GitHubAPIError(f"Repository not found: {owner}/{repo_name}", status_code=404)
            else:
                raise GitHubAPIError(f"Failed to get repository info for {owner}/{repo_name}: {e}")
    
    def get_repository_contents(self, repo_url: str, path: str = "", ref: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get repository contents at a specific path.
        
        Args:
            repo_url: GitHub repository URL
            path: Path within the repository
            ref: Git reference (branch, tag, or commit SHA)
            
        Returns:
            List of content items
            
        Raises:
            GitHubAPIError: If contents cannot be retrieved
        """
        owner, repo_name = self._parse_repo_url(repo_url)
        endpoint = f"/repos/{owner}/{repo_name}/contents/{path.lstrip('/')}"
        
        params = {}
        if ref:
            params["ref"] = ref
        
        try:
            response = self._make_request("GET", endpoint, params=params)
            contents = response.json()
            
            # Ensure we return a list
            if isinstance(contents, dict):
                contents = [contents]
            
            logger.debug(f"Retrieved {len(contents)} items from {owner}/{repo_name}:{path}")
            return contents
            
        except GitHubAPIError as e:
            if e.status_code == 404:
                logger.debug(f"Path not found in repository: {owner}/{repo_name}:{path}")
                return []
            else:
                raise GitHubAPIError(f"Failed to get repository contents for {owner}/{repo_name}:{path}: {e}")
    
    def get_file_content(self, repo_url: str, file_path: str, ref: Optional[str] = None) -> Optional[str]:
        """
        Get the content of a specific file from the repository.
        
        Args:
            repo_url: GitHub repository URL
            file_path: Path to the file
            ref: Git reference (branch, tag, or commit SHA)
            
        Returns:
            File content as string or None if file not found
            
        Raises:
            GitHubAPIError: If file content cannot be retrieved
        """
        try:
            contents = self.get_repository_contents(repo_url, file_path, ref)
            if not contents or len(contents) != 1:
                return None
            
            file_info = contents[0]
            if file_info.get("type") != "file":
                return None
            
            # Decode base64 content
            import base64
            content = base64.b64decode(file_info["content"]).decode("utf-8")
            return content
            
        except GitHubAPIError:
            return None
    
    def list_dependency_files(self, repo_url: str, ref: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List common dependency files in the repository.
        
        Args:
            repo_url: GitHub repository URL
            ref: Git reference (branch, tag, or commit SHA)
            
        Returns:
            List of dependency files found
        """
        dependency_files = [
            "package.json", "package-lock.json", "yarn.lock",  # Node.js
            "requirements.txt", "setup.py", "pyproject.toml", "Pipfile", "poetry.lock",  # Python
            "pom.xml", "build.gradle", "gradle.properties",  # Java
            "packages.config", "*.csproj", "*.fsproj", "*.vbproj",  # .NET
            "composer.json", "composer.lock",  # PHP
            "Gemfile", "Gemfile.lock",  # Ruby
            "Cargo.toml", "Cargo.lock",  # Rust
            "go.mod", "go.sum",  # Go
        ]
        
        found_files = []
        
        # Search in root directory
        try:
            root_contents = self.get_repository_contents(repo_url, "", ref)
            for item in root_contents:
                if item.get("type") == "file" and item.get("name") in dependency_files:
                    found_files.append({
                        "name": item["name"],
                        "path": item["path"],
                        "type": self._detect_file_type(item["name"]),
                        "size": item.get("size", 0),
                        "download_url": item.get("download_url")
                    })
        except GitHubAPIError as e:
            logger.warning(f"Failed to search root directory for dependency files: {e}")
        
        # TODO: Add recursive search for dependency files in subdirectories
        # This would be implemented in a future enhancement
        
        logger.info(f"Found {len(found_files)} dependency files in repository")
        return found_files
    
    def _detect_file_type(self, filename: str) -> str:
        """
        Detect the type of dependency file.
        
        Args:
            filename: Name of the file
            
        Returns:
            File type identifier
        """
        file_type_mapping = {
            "package.json": "npm",
            "package-lock.json": "npm",
            "yarn.lock": "yarn",
            "requirements.txt": "pip",
            "setup.py": "pip",
            "pyproject.toml": "poetry",
            "Pipfile": "pipenv",
            "poetry.lock": "poetry",
            "pom.xml": "maven",
            "build.gradle": "gradle",
            "gradle.properties": "gradle",
            "packages.config": "nuget",
            "composer.json": "composer",
            "composer.lock": "composer",
            "Gemfile": "bundler",
            "Gemfile.lock": "bundler",
            "Cargo.toml": "cargo",
            "Cargo.lock": "cargo",
            "go.mod": "go",
            "go.sum": "go"
        }
        
        # Handle .csproj, .fsproj, .vbproj files
        if filename.endswith((".csproj", ".fsproj", ".vbproj")):
            return "nuget"
        
        return file_type_mapping.get(filename, "unknown")
    
    def _parse_repo_url(self, repo_url: str) -> tuple[str, str]:
        """
        Parse GitHub repository URL to extract owner and repository name.
        
        Args:
            repo_url: GitHub repository URL
            
        Returns:
            Tuple of (owner, repository_name)
            
        Raises:
            ValueError: If URL format is invalid
        """
        # Handle various GitHub URL formats
        if repo_url.startswith("git@github.com:"):
            # SSH format: git@github.com:owner/repo.git
            path = repo_url.replace("git@github.com:", "")
        elif repo_url.startswith("https://github.com/"):
            # HTTPS format: https://github.com/owner/repo
            parsed = urlparse(repo_url)
            path = parsed.path.lstrip("/")
        else:
            # Assume it's already in owner/repo format
            path = repo_url
        
        # Remove .git suffix if present
        if path.endswith(".git"):
            path = path[:-4]
        
        # Split into owner and repo
        parts = path.split("/")
        if len(parts) != 2:
            raise ValueError(f"Invalid GitHub repository URL format: {repo_url}")
        
        return parts[0], parts[1]
    
    def create_repository_object(self, repo_url: str, local_path: str, branch: Optional[str] = None) -> Repository:
        """
        Create a Repository object with information from GitHub API.
        
        Args:
            repo_url: GitHub repository URL
            local_path: Local path where repository will be cloned
            branch: Branch to use (defaults to repository's default branch)
            
        Returns:
            Repository object with GitHub metadata
            
        Raises:
            GitHubAPIError: If repository information cannot be retrieved
        """
        try:
            repo_info = self.get_repository_info(repo_url)
            
            return Repository(
                url=repo_url,
                name=repo_info["name"],
                local_path=local_path,
                branch=branch or repo_info["default_branch"],
                access_token=self.access_token,
                owner=repo_info["owner"],
                description=repo_info.get("description"),
                language=repo_info.get("language"),
                stars=repo_info.get("stars", 0),
                forks=repo_info.get("forks", 0),
                last_updated=repo_info.get("last_updated"),
                metadata={
                    "clone_url": repo_info["clone_url"],
                    "ssh_url": repo_info["ssh_url"],
                    "html_url": repo_info["html_url"],
                    "private": repo_info.get("private", False),
                    "archived": repo_info.get("archived", False),
                    "disabled": repo_info.get("disabled", False),
                    "topics": repo_info.get("topics", []),
                    "license": repo_info.get("license")
                }
            )
            
        except GitHubAPIError as e:
            logger.error(f"Failed to create repository object for {repo_url}: {e}")
            raise