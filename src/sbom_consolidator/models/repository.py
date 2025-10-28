"""
Repository data model for GitHub repository information.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from pathlib import Path
import json


@dataclass
class Repository:
    """
    Represents a GitHub repository with metadata and local information.
    
    This class encapsulates all information needed to work with a GitHub
    repository, including authentication, local paths, and metadata.
    """
    
    url: str
    name: str
    local_path: str
    branch: str = "main"
    access_token: Optional[str] = None
    owner: Optional[str] = None
    description: Optional[str] = None
    language: Optional[str] = None
    stars: int = 0
    forks: int = 0
    last_updated: Optional[str] = None
    clone_status: str = "not_cloned"  # not_cloned, cloning, cloned, failed
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization processing to extract repository information."""
        if self.url and not self.name:
            # Extract repository name from URL
            self.name = self._extract_repo_name(self.url)
        
        if self.url and not self.owner:
            # Extract owner from URL
            self.owner = self._extract_owner(self.url)
    
    def _extract_repo_name(self, url: str) -> str:
        """
        Extract repository name from GitHub URL.
        
        Args:
            url: GitHub repository URL
            
        Returns:
            Repository name
        """
        # Handle various GitHub URL formats
        if url.endswith('.git'):
            url = url[:-4]
        
        parts = url.rstrip('/').split('/')
        return parts[-1] if parts else "unknown"
    
    def _extract_owner(self, url: str) -> str:
        """
        Extract owner/organization name from GitHub URL.
        
        Args:
            url: GitHub repository URL
            
        Returns:
            Owner/organization name
        """
        if url.endswith('.git'):
            url = url[:-4]
        
        parts = url.rstrip('/').split('/')
        return parts[-2] if len(parts) >= 2 else "unknown"
    
    @property
    def full_name(self) -> str:
        """Get the full repository name (owner/repo)."""
        return f"{self.owner}/{self.name}" if self.owner else self.name
    
    @property
    def local_path_obj(self) -> Path:
        """Get the local path as a Path object."""
        return Path(self.local_path)
    
    def is_cloned(self) -> bool:
        """Check if repository has been successfully cloned."""
        return self.clone_status == "cloned" and self.local_path_obj.exists()
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert repository to dictionary for serialization.
        
        Returns:
            Dictionary representation of the repository
        """
        return {
            "url": self.url,
            "name": self.name,
            "full_name": self.full_name,
            "owner": self.owner,
            "branch": self.branch,
            "local_path": self.local_path,
            "description": self.description,
            "language": self.language,
            "stars": self.stars,
            "forks": self.forks,
            "last_updated": self.last_updated,
            "clone_status": self.clone_status,
            "metadata": self.metadata
        }
    
    def to_json(self) -> str:
        """
        Convert repository to JSON string.
        
        Returns:
            JSON representation of the repository
        """
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Repository':
        """
        Create repository from dictionary.
        
        Args:
            data: Dictionary containing repository data
            
        Returns:
            Repository instance
        """
        return cls(
            url=data["url"],
            name=data.get("name", ""),
            local_path=data["local_path"],
            branch=data.get("branch", "main"),
            access_token=data.get("access_token"),
            owner=data.get("owner"),
            description=data.get("description"),
            language=data.get("language"),
            stars=data.get("stars", 0),
            forks=data.get("forks", 0),
            last_updated=data.get("last_updated"),
            clone_status=data.get("clone_status", "not_cloned"),
            metadata=data.get("metadata", {})
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> 'Repository':
        """
        Create repository from JSON string.
        
        Args:
            json_str: JSON string containing repository data
            
        Returns:
            Repository instance
        """
        data = json.loads(json_str)
        return cls.from_dict(data)