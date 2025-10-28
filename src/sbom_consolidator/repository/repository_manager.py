"""
Repository manager for cloning and managing GitHub repositories.
"""

import os
import shutil
import tempfile
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any
from contextlib import contextmanager
import git
from git import Repo, GitCommandError

from ..models import Repository
from ..config import get_config
from .github_client import GitHubClient, GitHubAPIError

logger = logging.getLogger(__name__)


class RepositoryManagerError(Exception):
    """Custom exception for repository management errors."""
    pass


class RepositoryManager:
    """
    Manages GitHub repository operations including cloning, cleanup, and file system management.
    
    This class handles the local file system operations for repositories including
    cloning, temporary directory management, and cleanup operations.
    """
    
    def __init__(self, github_client: Optional[GitHubClient] = None, temp_dir: Optional[str] = None):
        """
        Initialize repository manager.
        
        Args:
            github_client: GitHub API client instance
            temp_dir: Base directory for temporary repositories
        """
        self.github_client = github_client or GitHubClient()
        self.config = get_config()
        
        # Set up temporary directory
        self.temp_dir = Path(temp_dir) if temp_dir else Path(tempfile.gettempdir()) / "sbom_repos"
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
        # Track cloned repositories for cleanup
        self._cloned_repos: List[Repository] = []
        self._temp_directories: List[Path] = []
    
    def clone_repository(self, repo_url: str, branch: Optional[str] = None, depth: Optional[int] = 1) -> Repository:
        """
        Clone a GitHub repository to a temporary directory.
        
        Args:
            repo_url: GitHub repository URL
            branch: Branch to clone (defaults to repository's default branch)
            depth: Clone depth (1 for shallow clone, None for full clone)
            
        Returns:
            Repository object with local path information
            
        Raises:
            RepositoryManagerError: If cloning fails
        """
        try:
            # Get repository information from GitHub API
            repo_info = self.github_client.get_repository_info(repo_url)
            target_branch = branch or repo_info["default_branch"]
            
            # Create unique directory name
            repo_name = repo_info["name"]
            owner = repo_info["owner"]
            unique_name = f"{owner}_{repo_name}_{target_branch}"
            local_path = self.temp_dir / unique_name
            
            # Remove existing directory if it exists
            if local_path.exists():
                logger.info(f"Removing existing repository directory: {local_path}")
                shutil.rmtree(local_path)
            
            # Create repository object
            repository = Repository(
                url=repo_url,
                name=repo_name,
                local_path=str(local_path),
                branch=target_branch,
                access_token=self.github_client.access_token,
                owner=owner,
                description=repo_info.get("description"),
                language=repo_info.get("language"),
                stars=repo_info.get("stars", 0),
                forks=repo_info.get("forks", 0),
                last_updated=repo_info.get("last_updated"),
                clone_status="cloning",
                metadata=repo_info
            )
            
            logger.info(f"Cloning repository {owner}/{repo_name} (branch: {target_branch}) to {local_path}")
            
            # Prepare clone arguments
            clone_kwargs = {
                "branch": target_branch,
                "single_branch": True,
            }
            
            if depth is not None:
                clone_kwargs["depth"] = depth
            
            # Add authentication if available
            clone_url = repo_url
            if self.github_client.access_token and not repo_url.startswith("git@"):
                # Use HTTPS with token authentication
                if repo_url.startswith("https://github.com/"):
                    clone_url = repo_url.replace(
                        "https://github.com/",
                        f"https://{self.github_client.access_token}@github.com/"
                    )
            
            # Clone the repository
            try:
                git_repo = Repo.clone_from(clone_url, local_path, **clone_kwargs)
                repository.clone_status = "cloned"
                
                # Get additional repository information
                repository.metadata.update({
                    "commit_sha": git_repo.head.commit.hexsha,
                    "commit_message": git_repo.head.commit.message.strip(),
                    "commit_author": str(git_repo.head.commit.author),
                    "commit_date": git_repo.head.commit.committed_datetime.isoformat(),
                    "local_branch": git_repo.active_branch.name,
                    "remote_url": next(git_repo.remotes.origin.urls)
                })
                
                logger.info(f"Successfully cloned repository to {local_path}")
                
            except GitCommandError as e:
                repository.clone_status = "failed"
                error_msg = f"Git clone failed for {repo_url}: {e}"
                logger.error(error_msg)
                raise RepositoryManagerError(error_msg)
            
            # Track cloned repository for cleanup
            self._cloned_repos.append(repository)
            self._temp_directories.append(local_path)
            
            return repository
            
        except GitHubAPIError as e:
            error_msg = f"Failed to get repository information for {repo_url}: {e}"
            logger.error(error_msg)
            raise RepositoryManagerError(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error cloning repository {repo_url}: {e}"
            logger.error(error_msg)
            raise RepositoryManagerError(error_msg)
    
    def clone_repositories(self, repo_urls: List[str], branch: Optional[str] = None) -> List[Repository]:
        """
        Clone multiple repositories.
        
        Args:
            repo_urls: List of GitHub repository URLs
            branch: Branch to clone for all repositories
            
        Returns:
            List of Repository objects (successful clones only)
        """
        repositories = []
        failed_repos = []
        
        for repo_url in repo_urls:
            try:
                repository = self.clone_repository(repo_url, branch)
                repositories.append(repository)
                logger.info(f"Successfully cloned {repository.full_name}")
            except RepositoryManagerError as e:
                logger.error(f"Failed to clone {repo_url}: {e}")
                failed_repos.append(repo_url)
        
        if failed_repos:
            logger.warning(f"Failed to clone {len(failed_repos)} repositories: {failed_repos}")
        
        logger.info(f"Successfully cloned {len(repositories)} out of {len(repo_urls)} repositories")
        return repositories
    
    def update_repository(self, repository: Repository) -> bool:
        """
        Update a cloned repository by pulling latest changes.
        
        Args:
            repository: Repository object to update
            
        Returns:
            True if update was successful
        """
        if not repository.is_cloned():
            logger.error(f"Repository {repository.full_name} is not cloned")
            return False
        
        try:
            git_repo = Repo(repository.local_path)
            
            # Fetch latest changes
            origin = git_repo.remotes.origin
            origin.fetch()
            
            # Get current commit before pull
            old_commit = git_repo.head.commit.hexsha
            
            # Pull changes
            origin.pull()
            
            # Get new commit after pull
            new_commit = git_repo.head.commit.hexsha
            
            if old_commit != new_commit:
                logger.info(f"Updated repository {repository.full_name}: {old_commit[:8]} -> {new_commit[:8]}")
                
                # Update repository metadata
                repository.metadata.update({
                    "commit_sha": new_commit,
                    "commit_message": git_repo.head.commit.message.strip(),
                    "commit_author": str(git_repo.head.commit.author),
                    "commit_date": git_repo.head.commit.committed_datetime.isoformat(),
                })
            else:
                logger.info(f"Repository {repository.full_name} is already up to date")
            
            return True
            
        except GitCommandError as e:
            logger.error(f"Failed to update repository {repository.full_name}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error updating repository {repository.full_name}: {e}")
            return False
    
    def get_repository_files(self, repository: Repository, patterns: Optional[List[str]] = None) -> List[Path]:
        """
        Get list of files in the repository, optionally filtered by patterns.
        
        Args:
            repository: Repository object
            patterns: List of file patterns to match (glob patterns)
            
        Returns:
            List of file paths
        """
        if not repository.is_cloned():
            logger.error(f"Repository {repository.full_name} is not cloned")
            return []
        
        repo_path = Path(repository.local_path)
        files = []
        
        try:
            if patterns:
                # Use glob patterns to find files
                for pattern in patterns:
                    files.extend(repo_path.rglob(pattern))
            else:
                # Get all files recursively
                files = [f for f in repo_path.rglob("*") if f.is_file()]
            
            # Filter out .git directory and other hidden files
            files = [f for f in files if not any(part.startswith('.') for part in f.parts[len(repo_path.parts):])]
            
            logger.debug(f"Found {len(files)} files in repository {repository.full_name}")
            return files
            
        except Exception as e:
            logger.error(f"Error getting files from repository {repository.full_name}: {e}")
            return []
    
    def find_dependency_files(self, repository: Repository) -> Dict[str, List[Path]]:
        """
        Find dependency files in the repository.
        
        Args:
            repository: Repository object
            
        Returns:
            Dictionary mapping file types to lists of file paths
        """
        if not repository.is_cloned():
            logger.error(f"Repository {repository.full_name} is not cloned")
            return {}
        
        dependency_patterns = {
            "npm": ["package.json", "package-lock.json", "yarn.lock"],
            "pip": ["requirements.txt", "requirements-*.txt", "setup.py", "pyproject.toml"],
            "pipenv": ["Pipfile", "Pipfile.lock"],
            "poetry": ["pyproject.toml", "poetry.lock"],
            "maven": ["pom.xml"],
            "gradle": ["build.gradle", "build.gradle.kts", "gradle.properties"],
            "nuget": ["packages.config", "*.csproj", "*.fsproj", "*.vbproj"],
            "composer": ["composer.json", "composer.lock"],
            "bundler": ["Gemfile", "Gemfile.lock"],
            "cargo": ["Cargo.toml", "Cargo.lock"],
            "go": ["go.mod", "go.sum"]
        }
        
        found_files = {}
        repo_path = Path(repository.local_path)
        
        for file_type, patterns in dependency_patterns.items():
            type_files = []
            for pattern in patterns:
                matches = list(repo_path.rglob(pattern))
                # Filter out files in node_modules, .git, and other common ignore directories
                filtered_matches = [
                    f for f in matches 
                    if not any(ignore_dir in f.parts for ignore_dir in [
                        'node_modules', '.git', '__pycache__', '.venv', 'venv', 
                        'target', 'build', 'dist', '.gradle'
                    ])
                ]
                type_files.extend(filtered_matches)
            
            if type_files:
                found_files[file_type] = type_files
                logger.debug(f"Found {len(type_files)} {file_type} files in {repository.full_name}")
        
        total_files = sum(len(files) for files in found_files.values())
        logger.info(f"Found {total_files} dependency files across {len(found_files)} package managers in {repository.full_name}")
        
        return found_files
    
    def read_file_content(self, file_path: Path) -> Optional[str]:
        """
        Read the content of a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            File content as string or None if reading fails
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except UnicodeDecodeError:
            # Try with different encoding
            try:
                with open(file_path, 'r', encoding='latin-1') as f:
                    return f.read()
            except Exception as e:
                logger.warning(f"Failed to read file {file_path} with latin-1 encoding: {e}")
                return None
        except Exception as e:
            logger.warning(f"Failed to read file {file_path}: {e}")
            return None
    
    def cleanup_repository(self, repository: Repository) -> bool:
        """
        Clean up a single repository's local files.
        
        Args:
            repository: Repository to clean up
            
        Returns:
            True if cleanup was successful
        """
        if not repository.local_path:
            return True
        
        local_path = Path(repository.local_path)
        
        try:
            if local_path.exists():
                shutil.rmtree(local_path)
                logger.info(f"Cleaned up repository directory: {local_path}")
            
            # Remove from tracking lists
            if repository in self._cloned_repos:
                self._cloned_repos.remove(repository)
            if local_path in self._temp_directories:
                self._temp_directories.remove(local_path)
            
            repository.clone_status = "not_cloned"
            return True
            
        except Exception as e:
            logger.error(f"Failed to cleanup repository {repository.full_name}: {e}")
            return False
    
    def cleanup_all_repositories(self) -> int:
        """
        Clean up all cloned repositories.
        
        Returns:
            Number of repositories successfully cleaned up
        """
        cleaned_count = 0
        
        # Clean up tracked repositories
        for repository in self._cloned_repos.copy():
            if self.cleanup_repository(repository):
                cleaned_count += 1
        
        # Clean up any remaining temporary directories
        for temp_dir in self._temp_directories.copy():
            try:
                if temp_dir.exists():
                    shutil.rmtree(temp_dir)
                    logger.info(f"Cleaned up temporary directory: {temp_dir}")
                self._temp_directories.remove(temp_dir)
            except Exception as e:
                logger.error(f"Failed to cleanup temporary directory {temp_dir}: {e}")
        
        logger.info(f"Cleaned up {cleaned_count} repositories")
        return cleaned_count
    
    def get_repository_statistics(self, repository: Repository) -> Dict[str, Any]:
        """
        Get statistics about a repository.
        
        Args:
            repository: Repository object
            
        Returns:
            Dictionary of repository statistics
        """
        if not repository.is_cloned():
            return {"error": "Repository not cloned"}
        
        try:
            repo_path = Path(repository.local_path)
            
            # Count files by type
            all_files = self.get_repository_files(repository)
            file_extensions = {}
            total_size = 0
            
            for file_path in all_files:
                ext = file_path.suffix.lower()
                file_extensions[ext] = file_extensions.get(ext, 0) + 1
                try:
                    total_size += file_path.stat().st_size
                except OSError:
                    pass
            
            # Find dependency files
            dependency_files = self.find_dependency_files(repository)
            
            # Get git information
            git_info = {}
            try:
                git_repo = Repo(repository.local_path)
                git_info = {
                    "branch": git_repo.active_branch.name,
                    "commit_count": len(list(git_repo.iter_commits())),
                    "latest_commit": {
                        "sha": git_repo.head.commit.hexsha,
                        "message": git_repo.head.commit.message.strip(),
                        "author": str(git_repo.head.commit.author),
                        "date": git_repo.head.commit.committed_datetime.isoformat()
                    }
                }
            except Exception as e:
                logger.warning(f"Failed to get git information for {repository.full_name}: {e}")
            
            return {
                "repository": repository.full_name,
                "local_path": repository.local_path,
                "clone_status": repository.clone_status,
                "total_files": len(all_files),
                "total_size_bytes": total_size,
                "total_size_mb": round(total_size / (1024 * 1024), 2),
                "file_extensions": file_extensions,
                "dependency_files": {k: len(v) for k, v in dependency_files.items()},
                "git_info": git_info,
                "metadata": repository.metadata
            }
            
        except Exception as e:
            logger.error(f"Failed to get statistics for repository {repository.full_name}: {e}")
            return {"error": str(e)}
    
    @contextmanager
    def temporary_repository(self, repo_url: str, branch: Optional[str] = None):
        """
        Context manager for temporary repository cloning with automatic cleanup.
        
        Args:
            repo_url: GitHub repository URL
            branch: Branch to clone
            
        Yields:
            Repository object
        """
        repository = None
        try:
            repository = self.clone_repository(repo_url, branch)
            yield repository
        finally:
            if repository:
                self.cleanup_repository(repository)
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.cleanup_all_repositories()