import httpx
import asyncio
import feedparser
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json
import logging
import re
from src.models.database import Advisory, CVE
from src.models.schemas import Severity
from src.database.connection import get_db
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class AdvisoryIngestionService:
    def __init__(self):
        self.advisory_sources = {
            "cisa": {
                "url": "https://www.cisa.gov/news-events/cybersecurity-advisories",
                "type": "html"
            },
            "uscert": {
                "url": "https://www.us-cert.gov/ncas/current-activity",
                "type": "html"
            },
            "msrc": {
                "url": "https://msrc.microsoft.com/blog/feed",
                "type": "rss"
            },
            "apple_security": {
                "url": "https://support.apple.com/en-us/HT201222",
                "type": "html"
            },
            "redhat": {
                "url": "https://access.redhat.com/security/security-updates/",
                "type": "html"
            }
        }
    
    async def fetch_rss_feed(self, url: str) -> List[Dict[str, Any]]:
        """Fetch and parse RSS feed."""
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(url)
                response.raise_for_status()
                
                feed = feedparser.parse(response.content)
                entries = []
                
                for entry in feed.entries:
                    entry_data = {
                        "title": entry.get("title", ""),
                        "description": entry.get("description", "") or entry.get("summary", ""),
                        "url": entry.get("link", ""),
                        "published_date": self._parse_date(entry.get("published")),
                        "last_modified_date": self._parse_date(entry.get("updated")),
                        "id": entry.get("id", "") or entry.get("link", "")
                    }
                    entries.append(entry_data)
                
                return entries
                
            except Exception as e:
                logger.error(f"Error fetching RSS feed from {url}: {e}")
                return []
    
    async def fetch_html_content(self, url: str) -> List[Dict[str, Any]]:
        """Fetch and parse HTML content for advisories."""
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(url)
                response.raise_for_status()
                
                # This is a simplified parser - in production, you'd want more sophisticated parsing
                # based on the specific HTML structure of each source
                
                if "cisa.gov" in url:
                    return await self._parse_cisa_advisories(response.text)
                elif "us-cert.gov" in url:
                    return await self._parse_uscert_advisories(response.text)
                elif "apple.com" in url:
                    return await self._parse_apple_advisories(response.text)
                elif "redhat.com" in url:
                    return await self._parse_redhat_advisories(response.text)
                
            except Exception as e:
                logger.error(f"Error fetching HTML content from {url}: {e}")
                return []
        
        return []
    
    async def _parse_cisa_advisories(self, html: str) -> List[Dict[str, Any]]:
        """Parse CISA advisories from HTML."""
        
        # This would typically use BeautifulSoup or similar HTML parser
        # For now, returning a placeholder structure
        return [{
            "title": "Sample CISA Advisory",
            "description": "Sample advisory description",
            "url": "https://www.cisa.gov/sample-advisory",
            "published_date": datetime.utcnow(),
            "severity": "HIGH",
            "source": "CISA",
            "source_id": "cisa-sample-001"
        }]
    
    async def _parse_uscert_advisories(self, html: str) -> List[Dict[str, Any]]:
        """Parse US-CERT advisories from HTML."""
        return [{
            "title": "Sample US-CERT Advisory",
            "description": "Sample advisory description",
            "url": "https://www.us-cert.gov/sample-advisory",
            "published_date": datetime.utcnow(),
            "severity": "MEDIUM",
            "source": "US-CERT",
            "source_id": "uscert-sample-001"
        }]
    
    async def _parse_apple_advisories(self, html: str) -> List[Dict[str, Any]]:
        """Parse Apple security advisories from HTML."""
        return [{
            "title": "Apple Security Advisory",
            "description": "Sample Apple advisory description",
            "url": "https://support.apple.com/sample-advisory",
            "published_date": datetime.utcnow(),
            "severity": "HIGH",
            "source": "APPLE",
            "source_id": "apple-sample-001"
        }]
    
    async def _parse_redhat_advisories(self, html: str) -> List[Dict[str, Any]]:
        """Parse Red Hat security advisories from HTML."""
        return [{
            "title": "Red Hat Security Advisory",
            "description": "Sample Red Hat advisory description",
            "url": "https://access.redhat.com/sample-advisory",
            "published_date": datetime.utcnow(),
            "severity": "MEDIUM",
            "source": "REDHAT",
            "source_id": "rh-sample-001"
        }]
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse various date formats."""
        if not date_str:
            return None
        
        try:
            # Try common date formats
            formats = [
                "%a, %d %b %Y %H:%M:%S %Z",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d",
                "%Y-%m-%d %H:%M:%S"
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(date_str, fmt)
                except ValueError:
                    continue
            
            # Fallback to dateutil or just return current time
            return datetime.utcnow()
            
        except Exception:
            return datetime.utcnow()
    
    def _extract_severity(self, text: str) -> str:
        """Extract severity from text using keyword matching."""
        text_lower = text.lower()
        
        severity_keywords = {
            "critical": ["critical", "emergency", "urgent"],
            "high": ["high", "important", "severe"],
            "medium": ["medium", "moderate", "moderate"],
            "low": ["low", "minor", "informational"]
        }
        
        for severity, keywords in severity_keywords.items():
            if any(keyword in text_lower for keyword in keywords):
                return severity.upper()
        
        return "MEDIUM"  # Default severity
    
    def _extract_cve_references(self, text: str) -> List[str]:
        """Extract CVE IDs from text using regex."""
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        return list(set(re.findall(cve_pattern, text, re.IGNORECASE)))
    
    async def ingest_advisory(self, db: Session, advisory_data: Dict[str, Any]) -> bool:
        """Ingest a single advisory into the database."""
        
        try:
            # Check if advisory already exists
            existing = db.query(Advisory).filter(
                Advisory.source_id == advisory_data["source_id"],
                Advisory.source == advisory_data["source"]
            ).first()
            
            if existing:
                # Update existing advisory
                existing.title = advisory_data["title"]
                existing.description = advisory_data["description"]
                existing.last_modified_date = advisory_data.get("last_modified_date")
                existing.updated_at = datetime.utcnow()
            else:
                # Create new advisory
                advisory = Advisory(
                    title=advisory_data["title"],
                    description=advisory_data["description"],
                    source=advisory_data["source"],
                    source_id=advisory_data["source_id"],
                    url=advisory_data.get("url"),
                    published_date=advisory_data["published_date"],
                    last_modified_date=advisory_data.get("last_modified_date"),
                    severity=advisory_data.get("severity"),
                    category=advisory_data.get("category"),
                    affected_systems=advisory_data.get("affected_systems", []),
                    recommendations=advisory_data.get("recommendations"),
                    raw_data=advisory_data.get("raw_data", {})
                )
                db.add(advisory)
            
            return True
            
        except Exception as e:
            logger.error(f"Error ingesting advisory: {e}")
            return False
    
    async def ingest_all_advisories(self, db: Session) -> Dict[str, int]:
        """Ingest advisories from all configured sources."""
        
        logger.info("Starting advisory ingestion from all sources")
        
        processed = 0
        failed = 0
        
        for source_name, source_config in self.advisory_sources.items():
            try:
                if source_config["type"] == "rss":
                    advisories = await self.fetch_rss_feed(source_config["url"])
                else:
                    advisories = await self.fetch_html_content(source_config["url"])
                
                for advisory_data in advisories:
                    # Enrich advisory data
                    advisory_data["source"] = source_name.upper()
                    advisory_data["severity"] = self._extract_severity(
                        f"{advisory_data['title']} {advisory_data['description']}"
                    )
                    
                    # Extract CVE references
                    cve_refs = self._extract_cve_references(
                        f"{advisory_data['title']} {advisory_data['description']}"
                    )
                    advisory_data["cve_references"] = cve_refs
                    
                    if await self.ingest_advisory(db, advisory_data):
                        processed += 1
                    else:
                        failed += 1
                
                logger.info(f"Processed {len(advisories)} advisories from {source_name}")
                
            except Exception as e:
                logger.error(f"Error processing advisories from {source_name}: {e}")
                failed += 1
        
        try:
            db.commit()
            logger.info(f"Completed advisory ingestion: {processed} processed, {failed} failed")
        except Exception as e:
            logger.error(f"Error committing advisory data: {e}")
            db.rollback()
            failed += processed
            processed = 0
        
        return {"processed": processed, "failed": failed}
    
    async def get_advisory_count(self, db: Session) -> int:
        """Get total count of advisories in database."""
        return db.query(Advisory).count()
    
    async def get_advisories_by_source(self, db: Session, source: str) -> List[Advisory]:
        """Get advisories filtered by source."""
        return db.query(Advisory).filter(Advisory.source == source.upper()).all()