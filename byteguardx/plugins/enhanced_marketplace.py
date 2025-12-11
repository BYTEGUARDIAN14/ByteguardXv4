"""
Enhanced Plugin Marketplace for ByteGuardX
Author verification, reputation scoring, code preview, and security scanning
"""

import os
import json
import logging
import hashlib
import tempfile
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum

from ..database.connection_pool import db_manager
from ..database.models import Plugin, PluginAuthor, PluginReview, PluginDownload
from ..security.container_security import container_security_scanner

logger = logging.getLogger(__name__)

class AuthorVerificationStatus(Enum):
    """Author verification status"""
    UNVERIFIED = "unverified"
    PENDING = "pending"
    VERIFIED = "verified"
    TRUSTED = "trusted"
    SUSPENDED = "suspended"

class PluginSecurityRating(Enum):
    """Plugin security ratings"""
    UNKNOWN = "unknown"
    SAFE = "safe"
    LOW_RISK = "low_risk"
    MEDIUM_RISK = "medium_risk"
    HIGH_RISK = "high_risk"
    DANGEROUS = "dangerous"

@dataclass
class PluginAuthorInfo:
    """Plugin author information"""
    author_id: str
    username: str
    email: str
    verification_status: AuthorVerificationStatus
    reputation_score: float
    total_plugins: int
    total_downloads: int
    joined_date: datetime
    verification_date: Optional[datetime]
    bio: str
    website: Optional[str]

@dataclass
class PluginReputationScore:
    """Plugin reputation scoring"""
    overall_score: float
    download_score: float
    review_score: float
    security_score: float
    author_score: float
    freshness_score: float
    total_downloads: int
    average_rating: float
    total_reviews: int

@dataclass
class PluginMarketplaceInfo:
    """Complete plugin marketplace information"""
    plugin_id: str
    name: str
    description: str
    author: PluginAuthorInfo
    reputation: PluginReputationScore
    security_rating: PluginSecurityRating
    version: str
    file_size: int
    created_at: datetime
    updated_at: datetime
    tags: List[str]
    preview_code: str
    installation_count: int
    recent_reviews: List[Dict[str, Any]]

class EnhancedPluginMarketplace:
    """Enhanced plugin marketplace with security and reputation features"""
    
    def __init__(self):
        self.marketplace_storage = Path(os.environ.get('MARKETPLACE_STORAGE', 'data/marketplace'))
        self.preview_code_lines = 50  # Lines of code to show in preview
        self.min_reputation_for_auto_approval = 75.0
        
        # Ensure directories exist
        self.marketplace_storage.mkdir(parents=True, exist_ok=True)
    
    def submit_plugin(self, plugin_file_path: str, metadata: Dict[str, Any],
                     author_id: str) -> Dict[str, Any]:
        """
        Submit plugin to marketplace
        
        Args:
            plugin_file_path: Path to plugin file
            metadata: Plugin metadata
            author_id: Author identifier
            
        Returns:
            Dict containing submission results
        """
        try:
            # Validate plugin file
            if not Path(plugin_file_path).exists():
                return {"success": False, "error": "Plugin file not found"}
            
            # Security scan
            security_results = self._scan_plugin_security(plugin_file_path)
            
            # Code analysis
            code_analysis = self._analyze_plugin_code(plugin_file_path)
            
            # Generate preview
            preview_code = self._generate_code_preview(plugin_file_path)
            
            # Calculate initial reputation
            author_info = self._get_author_info(author_id)
            initial_reputation = self._calculate_initial_reputation(author_info, security_results)
            
            # Determine approval status
            auto_approved = (
                security_results['security_rating'] in ['safe', 'low_risk'] and
                initial_reputation >= self.min_reputation_for_auto_approval and
                author_info.verification_status in [AuthorVerificationStatus.VERIFIED, AuthorVerificationStatus.TRUSTED]
            )
            
            # Store plugin
            plugin_id = self._store_marketplace_plugin(
                plugin_file_path, metadata, author_id, security_results,
                code_analysis, preview_code, auto_approved
            )
            
            return {
                "success": True,
                "plugin_id": plugin_id,
                "auto_approved": auto_approved,
                "security_rating": security_results['security_rating'],
                "initial_reputation": initial_reputation,
                "requires_manual_review": not auto_approved
            }
            
        except Exception as e:
            logger.error(f"Failed to submit plugin: {e}")
            return {"success": False, "error": str(e)}
    
    def get_marketplace_listing(self, page: int = 1, page_size: int = 20,
                              category: str = None, sort_by: str = "reputation") -> Dict[str, Any]:
        """
        Get marketplace plugin listing
        
        Args:
            page: Page number
            page_size: Items per page
            category: Optional category filter
            sort_by: Sort criteria (reputation, downloads, recent, rating)
            
        Returns:
            Dict containing plugin listing
        """
        try:
            with db_manager.get_session() as session:
                # Base query
                query = session.query(Plugin).filter(Plugin.is_marketplace_approved == True)
                
                # Apply category filter
                if category:
                    query = query.filter(Plugin.category == category)
                
                # Apply sorting
                if sort_by == "downloads":
                    query = query.order_by(Plugin.download_count.desc())
                elif sort_by == "recent":
                    query = query.order_by(Plugin.updated_at.desc())
                elif sort_by == "rating":
                    query = query.order_by(Plugin.average_rating.desc())
                else:  # reputation
                    query = query.order_by(Plugin.reputation_score.desc())
                
                # Pagination
                offset = (page - 1) * page_size
                plugins = query.offset(offset).limit(page_size).all()
                total_count = query.count()
                
                # Build plugin info
                plugin_list = []
                for plugin in plugins:
                    plugin_info = self._build_marketplace_plugin_info(plugin)
                    plugin_list.append(plugin_info)
                
                return {
                    "plugins": plugin_list,
                    "total_count": total_count,
                    "page": page,
                    "page_size": page_size,
                    "total_pages": (total_count + page_size - 1) // page_size
                }
                
        except Exception as e:
            logger.error(f"Failed to get marketplace listing: {e}")
            return {"error": str(e)}
    
    def get_plugin_details(self, plugin_id: str) -> Optional[PluginMarketplaceInfo]:
        """
        Get detailed plugin information
        
        Args:
            plugin_id: Plugin identifier
            
        Returns:
            PluginMarketplaceInfo if found
        """
        try:
            with db_manager.get_session() as session:
                plugin = session.query(Plugin).filter(Plugin.id == plugin_id).first()
                
                if not plugin:
                    return None
                
                return self._build_marketplace_plugin_info(plugin)
                
        except Exception as e:
            logger.error(f"Failed to get plugin details: {e}")
            return None
    
    def verify_author(self, author_id: str, verification_data: Dict[str, Any]) -> bool:
        """
        Verify plugin author
        
        Args:
            author_id: Author identifier
            verification_data: Verification information
            
        Returns:
            True if verification successful
        """
        try:
            with db_manager.get_session() as session:
                author = session.query(PluginAuthor).filter(
                    PluginAuthor.id == author_id
                ).first()
                
                if not author:
                    return False
                
                # Perform verification checks
                verification_passed = self._perform_author_verification(verification_data)
                
                if verification_passed:
                    author.verification_status = AuthorVerificationStatus.VERIFIED.value
                    author.verification_date = datetime.now()
                    author.verification_metadata = json.dumps(verification_data)
                    
                    # Update reputation score
                    author.reputation_score = min(100.0, author.reputation_score + 20.0)
                    
                    session.commit()
                    
                    logger.info(f"Author {author_id} verified successfully")
                    return True
                
                return False
                
        except Exception as e:
            logger.error(f"Failed to verify author: {e}")
            return False
    
    def submit_review(self, plugin_id: str, user_id: str, rating: int,
                     review_text: str) -> bool:
        """
        Submit plugin review
        
        Args:
            plugin_id: Plugin identifier
            user_id: User identifier
            rating: Rating (1-5)
            review_text: Review text
            
        Returns:
            True if review submitted successfully
        """
        try:
            if not (1 <= rating <= 5):
                return False
            
            with db_manager.get_session() as session:
                # Check if user already reviewed this plugin
                existing_review = session.query(PluginReview).filter(
                    PluginReview.plugin_id == plugin_id,
                    PluginReview.user_id == user_id
                ).first()
                
                if existing_review:
                    # Update existing review
                    existing_review.rating = rating
                    existing_review.review_text = review_text
                    existing_review.updated_at = datetime.now()
                else:
                    # Create new review
                    review = PluginReview(
                        plugin_id=plugin_id,
                        user_id=user_id,
                        rating=rating,
                        review_text=review_text,
                        created_at=datetime.now()
                    )
                    session.add(review)
                
                session.commit()
                
                # Update plugin average rating
                self._update_plugin_rating(plugin_id)
                
                return True
                
        except Exception as e:
            logger.error(f"Failed to submit review: {e}")
            return False
    
    def track_download(self, plugin_id: str, user_id: str) -> bool:
        """
        Track plugin download
        
        Args:
            plugin_id: Plugin identifier
            user_id: User identifier
            
        Returns:
            True if tracked successfully
        """
        try:
            with db_manager.get_session() as session:
                # Record download
                download = PluginDownload(
                    plugin_id=plugin_id,
                    user_id=user_id,
                    downloaded_at=datetime.now()
                )
                session.add(download)
                
                # Update plugin download count
                plugin = session.query(Plugin).filter(Plugin.id == plugin_id).first()
                if plugin:
                    plugin.download_count = (plugin.download_count or 0) + 1
                    plugin.last_downloaded_at = datetime.now()
                
                session.commit()
                
                # Update reputation score
                self._update_plugin_reputation(plugin_id)
                
                return True
                
        except Exception as e:
            logger.error(f"Failed to track download: {e}")
            return False
    
    def _scan_plugin_security(self, plugin_file_path: str) -> Dict[str, Any]:
        """Scan plugin for security issues"""
        try:
            # Read plugin code
            with open(plugin_file_path, 'r') as f:
                code_content = f.read()
            
            # Security checks
            security_issues = []
            risk_score = 0
            
            # Check for dangerous imports
            dangerous_imports = ['os', 'subprocess', 'sys', 'eval', 'exec', 'open']
            for imp in dangerous_imports:
                if f"import {imp}" in code_content or f"from {imp}" in code_content:
                    security_issues.append(f"Potentially dangerous import: {imp}")
                    risk_score += 10
            
            # Check for file operations
            if any(op in code_content for op in ['open(', 'file(', 'write(', 'delete']):
                security_issues.append("File operations detected")
                risk_score += 5
            
            # Check for network operations
            if any(net in code_content for net in ['requests', 'urllib', 'socket', 'http']):
                security_issues.append("Network operations detected")
                risk_score += 5
            
            # Determine security rating
            if risk_score == 0:
                security_rating = PluginSecurityRating.SAFE
            elif risk_score <= 10:
                security_rating = PluginSecurityRating.LOW_RISK
            elif risk_score <= 25:
                security_rating = PluginSecurityRating.MEDIUM_RISK
            elif risk_score <= 50:
                security_rating = PluginSecurityRating.HIGH_RISK
            else:
                security_rating = PluginSecurityRating.DANGEROUS
            
            return {
                "security_rating": security_rating.value,
                "risk_score": risk_score,
                "security_issues": security_issues,
                "scan_timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Security scan failed: {e}")
            return {
                "security_rating": PluginSecurityRating.UNKNOWN.value,
                "error": str(e)
            }
    
    def _analyze_plugin_code(self, plugin_file_path: str) -> Dict[str, Any]:
        """Analyze plugin code quality and complexity"""
        try:
            with open(plugin_file_path, 'r') as f:
                code_content = f.read()
            
            lines = code_content.split('\n')
            total_lines = len(lines)
            code_lines = len([line for line in lines if line.strip() and not line.strip().startswith('#')])
            comment_lines = len([line for line in lines if line.strip().startswith('#')])
            
            # Simple complexity metrics
            function_count = code_content.count('def ')
            class_count = code_content.count('class ')
            
            return {
                "total_lines": total_lines,
                "code_lines": code_lines,
                "comment_lines": comment_lines,
                "comment_ratio": comment_lines / total_lines if total_lines > 0 else 0,
                "function_count": function_count,
                "class_count": class_count,
                "complexity_score": min(100, (code_lines / 10) + (function_count * 2) + (class_count * 5))
            }
            
        except Exception as e:
            logger.error(f"Code analysis failed: {e}")
            return {"error": str(e)}
    
    def _generate_code_preview(self, plugin_file_path: str) -> str:
        """Generate code preview for marketplace"""
        try:
            with open(plugin_file_path, 'r') as f:
                lines = f.readlines()
            
            # Take first N lines, excluding imports and comments at the top
            preview_lines = []
            skip_initial_comments = True
            
            for line in lines[:self.preview_code_lines]:
                stripped = line.strip()
                
                # Skip initial comments and docstrings
                if skip_initial_comments and (not stripped or stripped.startswith('#') or stripped.startswith('"""')):
                    continue
                
                skip_initial_comments = False
                preview_lines.append(line)
                
                if len(preview_lines) >= self.preview_code_lines:
                    break
            
            return ''.join(preview_lines)
            
        except Exception as e:
            logger.error(f"Failed to generate code preview: {e}")
            return "# Code preview unavailable"
    
    def _get_author_info(self, author_id: str) -> PluginAuthorInfo:
        """Get author information"""
        try:
            with db_manager.get_session() as session:
                author = session.query(PluginAuthor).filter(
                    PluginAuthor.id == author_id
                ).first()
                
                if not author:
                    # Create default author info
                    return PluginAuthorInfo(
                        author_id=author_id,
                        username="Unknown",
                        email="",
                        verification_status=AuthorVerificationStatus.UNVERIFIED,
                        reputation_score=0.0,
                        total_plugins=0,
                        total_downloads=0,
                        joined_date=datetime.now(),
                        verification_date=None,
                        bio="",
                        website=None
                    )
                
                return PluginAuthorInfo(
                    author_id=author.id,
                    username=author.username,
                    email=author.email,
                    verification_status=AuthorVerificationStatus(author.verification_status),
                    reputation_score=author.reputation_score,
                    total_plugins=author.total_plugins,
                    total_downloads=author.total_downloads,
                    joined_date=author.joined_date,
                    verification_date=author.verification_date,
                    bio=author.bio or "",
                    website=author.website
                )
                
        except Exception as e:
            logger.error(f"Failed to get author info: {e}")
            return PluginAuthorInfo(
                author_id=author_id,
                username="Error",
                email="",
                verification_status=AuthorVerificationStatus.UNVERIFIED,
                reputation_score=0.0,
                total_plugins=0,
                total_downloads=0,
                joined_date=datetime.now(),
                verification_date=None,
                bio="",
                website=None
            )
    
    def _calculate_initial_reputation(self, author_info: PluginAuthorInfo, 
                                    security_results: Dict[str, Any]) -> float:
        """Calculate initial reputation score for new plugin"""
        base_score = 50.0  # Base score
        
        # Author reputation contribution (30%)
        author_contribution = (author_info.reputation_score / 100.0) * 30.0
        
        # Security rating contribution (40%)
        security_ratings = {
            'safe': 40.0,
            'low_risk': 30.0,
            'medium_risk': 20.0,
            'high_risk': 10.0,
            'dangerous': 0.0,
            'unknown': 15.0
        }
        security_contribution = security_ratings.get(security_results.get('security_rating', 'unknown'), 15.0)
        
        # Verification status contribution (30%)
        verification_bonus = {
            AuthorVerificationStatus.TRUSTED: 30.0,
            AuthorVerificationStatus.VERIFIED: 20.0,
            AuthorVerificationStatus.PENDING: 10.0,
            AuthorVerificationStatus.UNVERIFIED: 0.0,
            AuthorVerificationStatus.SUSPENDED: -20.0
        }
        verification_contribution = verification_bonus.get(author_info.verification_status, 0.0)
        
        total_score = base_score + author_contribution + security_contribution + verification_contribution
        return max(0.0, min(100.0, total_score))
    
    def _store_marketplace_plugin(self, plugin_file_path: str, metadata: Dict[str, Any],
                                 author_id: str, security_results: Dict[str, Any],
                                 code_analysis: Dict[str, Any], preview_code: str,
                                 auto_approved: bool) -> str:
        """Store plugin in marketplace"""
        # Implementation would store plugin with all metadata
        # This is a simplified version
        plugin_id = f"plugin_{int(datetime.now().timestamp())}"
        
        # Store plugin file
        plugin_storage_path = self.marketplace_storage / f"{plugin_id}.py"
        with open(plugin_storage_path, 'w') as f:
            with open(plugin_file_path, 'r') as source:
                f.write(source.read())
        
        return plugin_id
    
    def _build_marketplace_plugin_info(self, plugin) -> Dict[str, Any]:
        """Build marketplace plugin information"""
        # This would build complete plugin info from database
        # Simplified version
        return {
            "plugin_id": plugin.id,
            "name": plugin.name,
            "description": plugin.description,
            "version": plugin.version,
            "author": "Author Name",  # Would get from author table
            "reputation_score": plugin.reputation_score or 0.0,
            "download_count": plugin.download_count or 0,
            "average_rating": plugin.average_rating or 0.0,
            "security_rating": "safe",  # Would get from security scan
            "created_at": plugin.created_at.isoformat() if plugin.created_at else None
        }
    
    def _perform_author_verification(self, verification_data: Dict[str, Any]) -> bool:
        """Perform author verification checks"""
        # Implementation would verify email, identity, etc.
        return True  # Simplified
    
    def _update_plugin_rating(self, plugin_id: str):
        """Update plugin average rating"""
        # Implementation would calculate average from reviews
        pass
    
    def _update_plugin_reputation(self, plugin_id: str):
        """Update plugin reputation score"""
        # Implementation would recalculate reputation based on downloads, reviews, etc.
        pass

# Global instance
enhanced_marketplace = EnhancedPluginMarketplace()
