import httpx
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json
import logging
from lxml import etree
from src.models.database import CVE, Vendor, Product, AffectedProduct
from src.models.schemas import CVEDetails
from src.database.connection import get_db
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class CVEIngestionService:
    def __init__(self):
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cve_search_base = "https://cve.circl.lu/api/"
        self.mitre_base = "https://cve.mitre.org/data/downloads/"
        
    async def fetch_cves_from_nvd(self,
                                start_date: Optional[datetime] = None,
                                end_date: Optional[datetime] = None,
                                results_per_page: int = 100) -> List[Dict[str, Any]]:
        """Fetch CVEs from NVD API with date filtering."""

        params = {
            "resultsPerPage": min(results_per_page, 100)  # NVD limits to 2000, but smaller batches are faster
        }

        # Use proper date format for NVD API (no microseconds, include timezone)
        if start_date:
            params["pubStartDate"] = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        if end_date:
            params["pubEndDate"] = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
            
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(self.nvd_api_base, params=params)
                response.raise_for_status()
                data = response.json()
                return data.get("vulnerabilities", [])
            except Exception as e:
                logger.error(f"Error fetching CVEs from NVD: {e}")
                return []
    
    async def fetch_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch detailed information for a specific CVE."""
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                # Try NVD API first
                url = f"{self.nvd_api_base}?cveId={cve_id}"
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    if vulnerabilities:
                        return vulnerabilities[0]
                
                # Fallback to CVE Search API
                search_url = f"{self.cve_search_base}cve/{cve_id}"
                response = await client.get(search_url)
                if response.status_code == 200:
                    return response.json()
                    
            except Exception as e:
                logger.error(f"Error fetching details for {cve_id}: {e}")
                
        return None
    
    def parse_nvd_cve(self, cve_data: Dict[str, Any]) -> CVEDetails:
        """Parse NVD CVE data into our CVE model."""
        
        cve_item = cve_data.get("cve", {})
        cve_id = cve_item.get("id", "")
        
        # Basic info
        descriptions = cve_item.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        
        # Dates
        published_date = datetime.fromisoformat(
            cve_item.get("published", "").replace("Z", "+00:00")
        )
        last_modified = datetime.fromisoformat(
            cve_item.get("lastModified", "").replace("Z", "+00:00")
        )
        
        # CVSS metrics
        metrics = cve_item.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
        cvss_v30 = metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
        cvss_v2 = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})
        
        # Use the latest available CVSS version
        cvss_data = cvss_v31 or cvss_v30 or cvss_v2
        
        cvss_score = cvss_data.get("baseScore")
        cvss_vector = cvss_data.get("vectorString")
        
        # Extract CVSS components
        attack_vector = cvss_data.get("attackVector")
        attack_complexity = cvss_data.get("attackComplexity")
        privileges_required = cvss_data.get("privilegesRequired")
        user_interaction = cvss_data.get("userInteraction")
        scope = cvss_data.get("scope")
        confidentiality_impact = cvss_data.get("confidentialityImpact")
        integrity_impact = cvss_data.get("integrityImpact")
        availability_impact = cvss_data.get("availabilityImpact")
        
        # Severity mapping
        severity = "UNKNOWN"
        if cvss_score >= 9.0:
            severity = "CRITICAL"
        elif cvss_score >= 7.0:
            severity = "HIGH"
        elif cvss_score >= 4.0:
            severity = "MEDIUM"
        elif cvss_score >= 0.1:
            severity = "LOW"
        else:
            severity = "INFO"
        
        return CVEDetails(
            id=0,  # Will be set by database
            cve_id=cve_id,
            description=description,
            published_date=published_date,
            last_modified_date=last_modified,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            attack_vector=attack_vector,
            attack_complexity=attack_complexity,
            privileges_required=privileges_required,
            user_interaction=user_interaction,
            scope=scope,
            confidentiality_impact=confidentiality_impact,
            integrity_impact=integrity_impact,
            availability_impact=availability_impact,
            source="NVD",
            raw_data=cve_data,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
    
    async def ingest_cves(self, db: Session,
                         start_date: Optional[datetime] = None,
                         end_date: Optional[datetime] = None) -> Dict[str, int]:
        """Main ingestion method."""

        # Use dates that actually have CVE data (recent past)
        if not start_date:
            start_date = datetime(2024, 12, 1)  # Start from Dec 2024
        if not end_date:
            end_date = datetime(2025, 1, 15)  # Up to mid-Jan 2025
            
        logger.info(f"Starting CVE ingestion from {start_date} to {end_date}")
        
        cves_data = await self.fetch_cves_from_nvd(start_date, end_date)
        
        processed = 0
        failed = 0
        
        for cve_data in cves_data:
            try:
                cve = self.parse_nvd_cve(cve_data)
                
                # Check if CVE already exists
                existing_cve = db.query(CVE).filter(CVE.cve_id == cve.cve_id).first()
                if existing_cve:
                    # Update existing CVE
                    existing_cve.description = cve.description
                    existing_cve.last_modified_date = cve.last_modified_date
                    existing_cve.severity = cve.severity
                    existing_cve.cvss_score = cve.cvss_score
                    existing_cve.cvss_vector = cve.cvss_vector
                    existing_cve.raw_data = cve.raw_data
                    existing_cve.updated_at = datetime.utcnow()
                else:
                    # Create new CVE
                    db_cve = CVE(
                        cve_id=cve.cve_id,
                        description=cve.description,
                        published_date=cve.published_date,
                        last_modified_date=cve.last_modified_date,
                        severity=cve.severity,
                        cvss_score=cve.cvss_score,
                        cvss_vector=cve.cvss_vector,
                        attack_vector=cve.attack_vector,
                        attack_complexity=cve.attack_complexity,
                        privileges_required=cve.privileges_required,
                        user_interaction=cve.user_interaction,
                        scope=cve.scope,
                        confidentiality_impact=cve.confidentiality_impact,
                        integrity_impact=cve.integrity_impact,
                        availability_impact=cve.availability_impact,
                        source=cve.source,
                        raw_data=cve.raw_data
                    )
                    db.add(db_cve)
                
                processed += 1
                
            except Exception as e:
                logger.error(f"Error processing CVE data: {e}")
                failed += 1
        
        try:
            db.commit()
            logger.info(f"Completed CVE ingestion: {processed} processed, {failed} failed")
        except Exception as e:
            logger.error(f"Error committing CVE data: {e}")
            db.rollback()
            failed = len(cves_data)
        
        return {"processed": processed, "failed": failed}
    
    async def get_cve_count(self, db: Session) -> int:
        """Get total count of CVEs in database."""
        return db.query(CVE).count()
    
    async def get_latest_cve_date(self, db: Session) -> Optional[datetime]:
        """Get the latest CVE publication date in database."""
        latest = db.query(CVE).order_by(CVE.published_date.desc()).first()
        return latest.published_date if latest else None