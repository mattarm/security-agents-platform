"""
GitHub Integration Client
Comprehensive GitHub analysis for enterprise topology mapping
"""

import asyncio
import aiohttp
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import re
import base64
from urllib.parse import urlparse

from github import Github, GithubException
from ...core.models.enterprise_models import GitHubRepository, Team

logger = logging.getLogger(__name__)

class GitHubEnterpriseClient:
    """Enterprise GitHub analysis and integration client"""
    
    def __init__(self, access_token: str, organization: str):
        """Initialize GitHub client"""
        self.github = Github(access_token)
        self.organization_name = organization
        self.organization = None
        self._session = None
        
    async def initialize(self) -> bool:
        """Initialize GitHub organization access"""
        try:
            self.organization = self.github.get_organization(self.organization_name)
            logger.info(f"Successfully connected to GitHub organization: {self.organization_name}")
            return True
        except GithubException as e:
            logger.error(f"Failed to connect to GitHub organization {self.organization_name}: {e}")
            return False
    
    async def get_all_repositories(self) -> List[GitHubRepository]:
        """Get all repositories in the organization"""
        repositories = []
        
        try:
            # Get all repos in organization
            for repo in self.organization.get_repos():
                try:
                    # Extract repository information
                    repo_data = await self._extract_repository_data(repo)
                    if repo_data:
                        repositories.append(repo_data)
                except Exception as e:
                    logger.error(f"Error processing repository {repo.name}: {e}")
                    continue
            
            logger.info(f"Retrieved {len(repositories)} repositories from {self.organization_name}")
            return repositories
            
        except GithubException as e:
            logger.error(f"Failed to retrieve repositories: {e}")
            return []
    
    async def _extract_repository_data(self, repo) -> Optional[GitHubRepository]:
        """Extract comprehensive repository data"""
        try:
            # Get CODEOWNERS information
            codeowners = await self._get_codeowners(repo)
            
            # Analyze commit patterns for ownership
            primary_contributors = await self._analyze_commit_patterns(repo)
            
            # Extract deployment information
            deployment_info = await self._analyze_deployment_configuration(repo)
            
            # Calculate security score
            security_score = await self._calculate_security_score(repo)
            
            # Determine owner team
            owner_team = await self._determine_owner_team(repo, codeowners, primary_contributors)
            
            return GitHubRepository(
                id=f"github_{repo.id}",
                name=repo.name,
                full_name=repo.full_name,
                organization=self.organization_name,
                primary_language=repo.language,
                owner_team=owner_team,
                codeowners=codeowners,
                is_private=repo.private,
                default_branch=repo.default_branch,
                last_commit_date=repo.updated_at,
                open_issues_count=repo.open_issues_count,
                security_score=security_score
            )
            
        except Exception as e:
            logger.error(f"Failed to extract data for repository {repo.name}: {e}")
            return None
    
    async def _get_codeowners(self, repo) -> List[str]:
        """Extract CODEOWNERS file information"""
        codeowners_paths = [
            ".github/CODEOWNERS",
            "CODEOWNERS", 
            "docs/CODEOWNERS"
        ]
        
        for path in codeowners_paths:
            try:
                codeowners_file = repo.get_contents(path)
                content = base64.b64decode(codeowners_file.content).decode('utf-8')
                
                # Parse CODEOWNERS content
                owners = []
                for line in content.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Extract team/user mentions
                        mentions = re.findall(r'@([a-zA-Z0-9_-]+/?[a-zA-Z0-9_-]*)', line)
                        owners.extend(mentions)
                
                return list(set(owners))  # Remove duplicates
                
            except:
                continue  # Try next path
        
        return []
    
    async def _analyze_commit_patterns(self, repo, days_back: int = 90) -> List[str]:
        """Analyze commit patterns to identify primary contributors"""
        try:
            since_date = datetime.now() - timedelta(days=days_back)
            commits = repo.get_commits(since=since_date)
            
            # Count commits by author
            author_counts = {}
            for commit in commits:
                if commit.author:
                    author_login = commit.author.login
                    author_counts[author_login] = author_counts.get(author_login, 0) + 1
            
            # Sort by commit count and return top contributors
            sorted_authors = sorted(author_counts.items(), key=lambda x: x[1], reverse=True)
            return [author for author, count in sorted_authors[:5]]  # Top 5 contributors
            
        except Exception as e:
            logger.error(f"Failed to analyze commit patterns for {repo.name}: {e}")
            return []
    
    async def _analyze_deployment_configuration(self, repo) -> Dict[str, Any]:
        """Analyze deployment configuration and CI/CD setup"""
        deployment_info = {
            "has_dockerfile": False,
            "has_kubernetes": False,
            "has_ci_cd": False,
            "deployment_environments": [],
            "deployment_targets": []
        }
        
        try:
            # Check for Dockerfile
            try:
                repo.get_contents("Dockerfile")
                deployment_info["has_dockerfile"] = True
            except:
                pass
            
            # Check for Kubernetes manifests
            try:
                k8s_files = repo.get_contents("k8s", ref=repo.default_branch)
                if k8s_files:
                    deployment_info["has_kubernetes"] = True
                    deployment_info["deployment_targets"].append("kubernetes")
            except:
                pass
            
            # Check for GitHub Actions
            try:
                workflows = repo.get_contents(".github/workflows")
                if workflows:
                    deployment_info["has_ci_cd"] = True
                    
                    # Analyze workflow files for deployment environments
                    for workflow in workflows:
                        if workflow.type == "file":
                            content = base64.b64decode(workflow.content).decode('utf-8')
                            
                            # Look for environment indicators
                            environments = re.findall(r'environment:\s*(\w+)', content)
                            deployment_info["deployment_environments"].extend(environments)
                            
                            # Look for deployment targets
                            if 'aws' in content.lower():
                                deployment_info["deployment_targets"].append("aws")
                            if 'azure' in content.lower():
                                deployment_info["deployment_targets"].append("azure")
                            if 'gcp' in content.lower():
                                deployment_info["deployment_targets"].append("gcp")
            except:
                pass
            
            # Remove duplicates
            deployment_info["deployment_environments"] = list(set(deployment_info["deployment_environments"]))
            deployment_info["deployment_targets"] = list(set(deployment_info["deployment_targets"]))
            
        except Exception as e:
            logger.error(f"Failed to analyze deployment config for {repo.name}: {e}")
        
        return deployment_info
    
    async def _calculate_security_score(self, repo) -> float:
        """Calculate security score for repository"""
        score = 1.0
        
        try:
            # Check for security best practices
            security_factors = {
                "has_security_md": 0.1,
                "has_dependabot": 0.2,
                "has_code_scanning": 0.2,
                "has_branch_protection": 0.3,
                "recent_security_updates": 0.2
            }
            
            # Check for SECURITY.md
            try:
                repo.get_contents("SECURITY.md")
                score += security_factors["has_security_md"]
            except:
                pass
            
            # Check for Dependabot configuration
            try:
                repo.get_contents(".github/dependabot.yml")
                score += security_factors["has_dependabot"]
            except:
                pass
            
            # Check branch protection
            try:
                branch = repo.get_branch(repo.default_branch)
                if branch.protected:
                    score += security_factors["has_branch_protection"]
            except:
                pass
            
            # Normalize score to 0-1 range
            return min(1.0, score)
            
        except Exception as e:
            logger.error(f"Failed to calculate security score for {repo.name}: {e}")
            return 0.5  # Default moderate score
    
    async def _determine_owner_team(self, repo, codeowners: List[str], 
                                   contributors: List[str]) -> str:
        """Determine the primary owner team for a repository"""
        # Priority: CODEOWNERS teams > repository name patterns > primary contributors
        
        # Check CODEOWNERS for team mentions
        for owner in codeowners:
            if '/' in owner:  # Team format: org/team
                return owner.split('/')[-1]
        
        # Check repository name for team patterns
        repo_name = repo.name.lower()
        team_patterns = {
            'frontend': ['frontend', 'ui', 'web', 'react', 'vue', 'angular'],
            'backend': ['backend', 'api', 'service', 'server'],
            'data': ['data', 'etl', 'analytics', 'ml', 'ai'],
            'platform': ['platform', 'infra', 'ops', 'deploy'],
            'security': ['security', 'auth', 'sec']
        }
        
        for team, keywords in team_patterns.items():
            if any(keyword in repo_name for keyword in keywords):
                return f"{team}-team"
        
        # Default to first contributor if available
        if contributors:
            return f"{contributors[0]}-team"
        
        return "unknown-team"
    
    async def get_repository_dependencies(self, repo_name: str) -> Dict[str, Any]:
        """Analyze repository dependencies"""
        try:
            repo = self.organization.get_repo(repo_name)
            dependencies = {
                "internal_dependencies": [],
                "external_dependencies": [],
                "dependency_files": []
            }
            
            # Dependency files to analyze
            dep_files = [
                ("package.json", self._parse_npm_dependencies),
                ("requirements.txt", self._parse_python_dependencies),
                ("pom.xml", self._parse_maven_dependencies),
                ("go.mod", self._parse_go_dependencies),
                ("Gemfile", self._parse_ruby_dependencies)
            ]
            
            for filename, parser in dep_files:
                try:
                    file_content = repo.get_contents(filename)
                    content = base64.b64decode(file_content.content).decode('utf-8')
                    
                    deps = await parser(content)
                    dependencies["dependency_files"].append(filename)
                    
                    # Categorize dependencies as internal/external
                    for dep in deps:
                        if await self._is_internal_dependency(dep):
                            dependencies["internal_dependencies"].append(dep)
                        else:
                            dependencies["external_dependencies"].append(dep)
                            
                except:
                    continue  # File doesn't exist
            
            return dependencies
            
        except Exception as e:
            logger.error(f"Failed to analyze dependencies for {repo_name}: {e}")
            return {}
    
    async def _parse_npm_dependencies(self, content: str) -> List[str]:
        """Parse NPM package.json dependencies"""
        import json
        try:
            package_data = json.loads(content)
            deps = []
            
            for section in ['dependencies', 'devDependencies', 'peerDependencies']:
                if section in package_data:
                    deps.extend(package_data[section].keys())
            
            return deps
        except:
            return []
    
    async def _parse_python_dependencies(self, content: str) -> List[str]:
        """Parse Python requirements.txt dependencies"""
        deps = []
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                # Extract package name (before version specifiers)
                dep_name = re.split(r'[>=<!\s]', line)[0]
                if dep_name:
                    deps.append(dep_name)
        return deps
    
    async def _parse_maven_dependencies(self, content: str) -> List[str]:
        """Parse Maven pom.xml dependencies"""
        deps = []
        # Simple regex to extract artifactId from Maven dependencies
        artifacts = re.findall(r'<artifactId>([^<]+)</artifactId>', content)
        return artifacts
    
    async def _parse_go_dependencies(self, content: str) -> List[str]:
        """Parse Go mod dependencies"""
        deps = []
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('require'):
                continue  # Skip require block start
            if line and not line.startswith('//') and ' ' in line:
                dep_name = line.split()[0]
                if dep_name != ')':  # Skip require block end
                    deps.append(dep_name)
        return deps
    
    async def _parse_ruby_dependencies(self, content: str) -> List[str]:
        """Parse Ruby Gemfile dependencies"""
        deps = []
        gem_pattern = r"gem\s+['\"]([^'\"]+)['\"]"
        gems = re.findall(gem_pattern, content)
        return gems
    
    async def _is_internal_dependency(self, dependency: str) -> bool:
        """Check if dependency is internal to the organization"""
        # Check if dependency matches organization namespace
        org_patterns = [
            f"@{self.organization_name}/",  # NPM scoped packages
            f"{self.organization_name}/",   # General org pattern
            f"com.{self.organization_name}.",  # Maven group pattern
        ]
        
        for pattern in org_patterns:
            if pattern.lower() in dependency.lower():
                return True
        
        return False
    
    async def map_repositories_to_teams(self) -> Dict[str, List[str]]:
        """Map repositories to their owner teams"""
        team_repo_mapping = {}
        
        try:
            repositories = await self.get_all_repositories()
            
            for repo in repositories:
                team = repo.owner_team
                if team not in team_repo_mapping:
                    team_repo_mapping[team] = []
                team_repo_mapping[team].append(repo.name)
            
            return team_repo_mapping
            
        except Exception as e:
            logger.error(f"Failed to map repositories to teams: {e}")
            return {}
    
    async def find_deployment_relationships(self) -> List[Dict[str, Any]]:
        """Find relationships between repositories and deployment targets"""
        relationships = []
        
        try:
            repositories = await self.get_all_repositories()
            
            for repo in repositories:
                # Get deployment configuration
                deployment_info = await self._analyze_deployment_configuration(
                    self.organization.get_repo(repo.name)
                )
                
                # Create relationships for each deployment target
                for target in deployment_info["deployment_targets"]:
                    relationships.append({
                        "repository": repo.name,
                        "deployment_target": target,
                        "environments": deployment_info["deployment_environments"],
                        "has_ci_cd": deployment_info["has_ci_cd"]
                    })
            
            return relationships
            
        except Exception as e:
            logger.error(f"Failed to find deployment relationships: {e}")
            return []
    
    def close(self):
        """Close GitHub client"""
        # GitHub client doesn't need explicit closure
        pass

class GitHubAnalytics:
    """Advanced GitHub analytics for enterprise insights"""
    
    def __init__(self, github_client: GitHubEnterpriseClient):
        self.github_client = github_client
    
    async def analyze_development_velocity(self, days_back: int = 30) -> Dict[str, Any]:
        """Analyze development velocity across the organization"""
        try:
            repos = await self.github_client.get_all_repositories()
            velocity_data = {
                "total_repositories": len(repos),
                "active_repositories": 0,
                "total_commits": 0,
                "total_pull_requests": 0,
                "team_velocity": {}
            }
            
            since_date = datetime.now() - timedelta(days=days_back)
            
            for repo in repos:
                try:
                    gh_repo = self.github_client.organization.get_repo(repo.name)
                    
                    # Count recent commits
                    commits = gh_repo.get_commits(since=since_date)
                    commit_count = sum(1 for _ in commits)
                    
                    # Count recent pull requests
                    prs = gh_repo.get_pulls(state='all', sort='updated', direction='desc')
                    pr_count = sum(1 for pr in prs if pr.updated_at >= since_date)
                    
                    if commit_count > 0 or pr_count > 0:
                        velocity_data["active_repositories"] += 1
                    
                    velocity_data["total_commits"] += commit_count
                    velocity_data["total_pull_requests"] += pr_count
                    
                    # Track by team
                    team = repo.owner_team
                    if team not in velocity_data["team_velocity"]:
                        velocity_data["team_velocity"][team] = {
                            "commits": 0,
                            "pull_requests": 0,
                            "repositories": 0
                        }
                    
                    velocity_data["team_velocity"][team]["commits"] += commit_count
                    velocity_data["team_velocity"][team]["pull_requests"] += pr_count
                    velocity_data["team_velocity"][team]["repositories"] += 1
                    
                except Exception as e:
                    logger.error(f"Error analyzing velocity for {repo.name}: {e}")
                    continue
            
            return velocity_data
            
        except Exception as e:
            logger.error(f"Failed to analyze development velocity: {e}")
            return {}
    
    async def identify_high_risk_repositories(self) -> List[Dict[str, Any]]:
        """Identify repositories with high risk factors"""
        risk_repos = []
        
        try:
            repos = await self.github_client.get_all_repositories()
            
            for repo in repos:
                risk_factors = []
                risk_score = 0.0
                
                # Low security score
                if repo.security_score < 0.5:
                    risk_factors.append("low_security_score")
                    risk_score += 0.3
                
                # High number of open issues
                if repo.open_issues_count and repo.open_issues_count > 20:
                    risk_factors.append("high_open_issues")
                    risk_score += 0.2
                
                # No clear owner
                if repo.owner_team == "unknown-team":
                    risk_factors.append("unclear_ownership")
                    risk_score += 0.4
                
                # No CODEOWNERS
                if not repo.codeowners:
                    risk_factors.append("no_codeowners")
                    risk_score += 0.1
                
                if risk_score > 0.5:  # High risk threshold
                    risk_repos.append({
                        "repository": repo.name,
                        "owner_team": repo.owner_team,
                        "risk_score": min(1.0, risk_score),
                        "risk_factors": risk_factors,
                        "security_score": repo.security_score,
                        "open_issues": repo.open_issues_count
                    })
            
            # Sort by risk score
            risk_repos.sort(key=lambda x: x["risk_score"], reverse=True)
            return risk_repos
            
        except Exception as e:
            logger.error(f"Failed to identify high risk repositories: {e}")
            return []