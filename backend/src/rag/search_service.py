import os
import logging
import re
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import json
from src.rag.embedding_service import EmbeddingService
from src.models.database import CVE, Advisory, SearchLog
from src.models.schemas import SearchResult, SearchResponse, Severity
from src.database.connection import get_db
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, text

logger = logging.getLogger(__name__)


def sanitize_search_input(input_str: str) -> str:
    """Sanitize user input to prevent SQL injection."""
    if not input_str:
        return ""
    # Remove SQL special characters and limit to alphanumeric, spaces, and basic punctuation
    # Allow CVE format (CVE-YYYY-NNNNN)
    sanitized = re.sub(r'[^\w\s\-.,!?@#]', '', input_str)
    # Limit length to prevent DoS
    return sanitized[:500]


class RAGPipeline:
    def __init__(self):
        self.embedding_service = EmbeddingService()
        
    def _extract_keywords(self, query: str) -> List[str]:
        """Extract relevant keywords from the query."""
        import re
        
        # Extract CVE IDs
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        cves = re.findall(cve_pattern, query.upper())
        
        # Extract severity keywords
        severity_keywords = []
        for severity in Severity:
            if severity.lower() in query.lower():
                severity_keywords.append(severity.value)
        
        # Extract other important terms
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 
                     'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
                     'what', 'when', 'where', 'why', 'how', 'show', 'tell', 'find', 'search',
                     'vulnerability', 'vulnerabilities', 'cve', 'advisory', 'security'}
        
        words = re.findall(r'\b\w+\b', query.lower())
        keywords = [word for word in words if word not in stop_words and len(word) > 2]
        
        return cves + severity_keywords + keywords
    
    def _search_database(self, db: Session, query: str, keywords: List[str],
                        severity_filter: Optional[List[Severity]] = None,
                        date_range: Optional[Dict[str, datetime]] = None) -> List[SearchResult]:
        """Search the database using traditional keyword matching."""

        results = []

        # Build CVE query
        cve_query = db.query(CVE)

        # Add keyword filtering with sanitization
        if keywords:
            keyword_conditions = []
            for keyword in keywords:
                # Sanitize each keyword to prevent SQL injection
                safe_keyword = sanitize_search_input(keyword)
                if safe_keyword:  # Only add if not empty after sanitization
                    keyword_conditions.append(
                        or_(
                            CVE.cve_id.ilike(f'%{safe_keyword}%'),
                            CVE.description.ilike(f'%{safe_keyword}%'),
                            CVE.attack_vector.ilike(f'%{safe_keyword}%'),
                            CVE.source.ilike(f'%{safe_keyword}%')
                        )
                    )
            if keyword_conditions:
                cve_query = cve_query.filter(and_(*keyword_conditions))
        
        # Add severity filter
        if severity_filter:
            cve_query = cve_query.filter(CVE.severity.in_([s.value for s in severity_filter]))
        
        # Add date range filter
        if date_range:
            if "start" in date_range:
                cve_query = cve_query.filter(CVE.published_date >= date_range["start"])
            if "end" in date_range:
                cve_query = cve_query.filter(CVE.published_date <= date_range["end"])
        
        # Execute query with limit
        cves = cve_query.limit(20).all()
        
        for cve in cves:
            relevance_score = self._calculate_relevance_score(query, keywords, cve)
            results.append(SearchResult(
                content_type="cve",
                content_id=cve.id,
                title=cve.cve_id,
                description=cve.description,
                relevance_score=relevance_score,
                metadata={
                    "severity": cve.severity,
                    "cvss_score": cve.cvss_score,
                    "published_date": cve.published_date.isoformat(),
                    "attack_vector": cve.attack_vector
                }
            ))
        
        # Build Advisory query
        advisory_query = db.query(Advisory)

        # Add keyword filtering with sanitization
        if keywords:
            keyword_conditions = []
            for keyword in keywords:
                # Sanitize each keyword to prevent SQL injection
                safe_keyword = sanitize_search_input(keyword)
                if safe_keyword:  # Only add if not empty after sanitization
                    keyword_conditions.append(
                        or_(
                            Advisory.title.ilike(f'%{safe_keyword}%'),
                            Advisory.description.ilike(f'%{safe_keyword}%'),
                            Advisory.source.ilike(f'%{safe_keyword}%'),
                            Advisory.category.ilike(f'%{safe_keyword}%')
                        )
                    )
            if keyword_conditions:
                advisory_query = advisory_query.filter(and_(*keyword_conditions))
        
        # Add severity filter
        if severity_filter:
            advisory_query = advisory_query.filter(Advisory.severity.in_([s.value for s in severity_filter]))
        
        # Add date range filter
        if date_range:
            if "start" in date_range:
                advisory_query = advisory_query.filter(Advisory.published_date >= date_range["start"])
            if "end" in date_range:
                advisory_query = advisory_query.filter(Advisory.published_date <= date_range["end"])
        
        # Execute query with limit
        advisories = advisory_query.limit(20).all()
        
        for advisory in advisories:
            relevance_score = self._calculate_relevance_score(query, keywords, advisory)
            results.append(SearchResult(
                content_type="advisory",
                content_id=advisory.id,
                title=advisory.title,
                description=advisory.description,
                relevance_score=relevance_score,
                metadata={
                    "source": advisory.source,
                    "severity": advisory.severity,
                    "published_date": advisory.published_date.isoformat(),
                    "url": advisory.url
                }
            ))
        
        return results
    
    def _calculate_relevance_score(self, query: str, keywords: List[str], 
                                  item: Any) -> float:
        """Calculate relevance score for a search result."""
        
        score = 0.0
        query_lower = query.lower()
        
        # Exact CVE ID match gets highest score
        if hasattr(item, 'cve_id'):
            cve_pattern = r'CVE-\d{4}-\d{4,}'
            query_cves = [cve.upper() for cve in keywords if cve.startswith('CVE-')]
            if item.cve_id.upper() in query_cves:
                score += 1.0
        
        # Severity matching
        if hasattr(item, 'severity') and item.severity:
            severity_keywords = ['critical', 'high', 'medium', 'low']
            for severity in severity_keywords:
                if severity in query_lower and severity == item.severity.lower():
                    score += 0.5
                    break
        
        # Keyword matching in text
        if hasattr(item, 'description') and item.description:
            desc_lower = item.description.lower()
            keyword_matches = sum(1 for kw in keywords if kw.lower() in desc_lower)
            score += (keyword_matches / len(keywords)) * 0.3
        
        # Title matching
        title_text = ""
        if hasattr(item, 'title'):
            title_text = item.title.lower()
        elif hasattr(item, 'cve_id'):
            title_text = item.cve_id.lower()
        
        title_matches = sum(1 for kw in keywords if kw.lower() in title_text)
        score += (title_matches / len(keywords)) * 0.2
        
        return min(score, 1.0)  # Cap at 1.0
    
    def _merge_and_rank_results(self, db_results: List[SearchResult], 
                               vector_results: Dict[str, List[Dict[str, Any]]],
                               query: str) -> List[SearchResult]:
        """Merge and rank results from database and vector search."""
        
        all_results = db_results.copy()
        
        # Process CVE vector results
        if "cve" in vector_results:
            for result in vector_results["cve"]:
                metadata = result["metadata"]
                all_results.append(SearchResult(
                    content_type="cve",
                    content_id=int(result["id"].split("_")[1]),
                    title=metadata["cve_id"],
                    description=result["document"],
                    relevance_score=result["similarity"],
                    metadata={
                        "severity": metadata["severity"],
                        "cvss_score": metadata["cvss_score"],
                        "source": metadata["source"]
                    }
                ))
        
        # Process advisory vector results
        if "advisory" in vector_results:
            for result in vector_results["advisory"]:
                metadata = result["metadata"]
                all_results.append(SearchResult(
                    content_type="advisory",
                    content_id=int(result["id"].split("_")[1]),
                    title=f"Advisory from {metadata['source']}",
                    description=result["document"],
                    relevance_score=result["similarity"],
                    metadata={
                        "source": metadata["source"],
                        "severity": metadata["severity"],
                        "published_date": metadata["published_date"]
                    }
                ))
        
        # Remove duplicates and sort by relevance score
        seen = set()
        unique_results = []
        
        for result in all_results:
            key = (result.content_type, result.content_id)
            if key not in seen:
                seen.add(key)
                unique_results.append(result)
        
        # Sort by relevance score (descending)
        unique_results.sort(key=lambda x: x.relevance_score, reverse=True)
        
        return unique_results
    
    async def search(self, db: Session, query: str, 
                    limit: int = 10,
                    severity_filter: Optional[List[Severity]] = None,
                    date_range: Optional[Dict[str, datetime]] = None,
                    content_types: Optional[List[str]] = None) -> SearchResponse:
        """Main search method using RAG pipeline."""
        
        start_time = datetime.now()
        
        # Log the search
        search_log = SearchLog(
            query=query,
            user_ip="localhost",  # Would be extracted from request in real implementation
            user_agent="vectorguard-api"
        )
        db.add(search_log)
        
        try:
            # Extract keywords
            keywords = self._extract_keywords(query)
            
            # Perform database search
            db_results = self._search_database(
                db, query, keywords, severity_filter, date_range
            )
            
            # Perform vector search
            vector_results = self.embedding_service.hybrid_search(
                query, content_types, limit * 2
            )
            
            # Merge and rank results
            all_results = self._merge_and_rank_results(db_results, vector_results, query)
            
            # Apply limit
            final_results = all_results[:limit]
            
            # Calculate response time
            response_time = (datetime.now() - start_time).total_seconds() * 1000
            
            # Update search log
            search_log.response_time_ms = int(response_time)
            search_log.result_count = len(final_results)
            db.commit()
            
            return SearchResponse(
                query=query,
                results=final_results,
                total_results=len(all_results),
                response_time_ms=int(response_time)
            )
            
        except Exception as e:
            logger.error(f"Error during search: {e}")
            db.rollback()
            
            # Return empty response
            response_time = (datetime.now() - start_time).total_seconds() * 1000
            return SearchResponse(
                query=query,
                results=[],
                total_results=0,
                response_time_ms=int(response_time)
            )
    
    async def get_search_suggestions(self, db: Session, partial_query: str) -> List[str]:
        """Get search suggestions based on partial query."""
        
        suggestions = []
        
        # CVE ID suggestions
        if partial_query.upper().startswith('CVE'):
            cves = db.query(CVE.cve_id).filter(
                CVE.cve_id.ilike(f'%{partial_query}%')
            ).limit(5).all()
            suggestions.extend([cve[0] for cve in cves])
        
        # Severity suggestions
        if len(partial_query) > 2:
            severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            for severity in severities:
                if partial_query.lower() in severity.lower():
                    suggestions.append(severity)
        
        # Common attack vectors
        attack_vectors = ['NETWORK', 'LOCAL', 'ADJACENT', 'PHYSICAL']
        if len(partial_query) > 2:
            for av in attack_vectors:
                if partial_query.lower() in av.lower():
                    suggestions.append(av)
        
        # Source suggestions
        sources = ['NVD', 'CISA', 'US-CERT', 'APPLE', 'REDHAT', 'MICROSOFT']
        for source in sources:
            if partial_query.lower() in source.lower():
                suggestions.append(source)
        
        return suggestions[:10]  # Limit to 10 suggestions
    
    def get_search_stats(self, db: Session, days: int = 30) -> Dict[str, Any]:
        """Get search statistics."""
        
        since_date = datetime.utcnow() - timedelta(days=days)
        
        total_searches = db.query(SearchLog).filter(
            SearchLog.created_at >= since_date
        ).count()
        
        avg_response_time = db.query(
            func.avg(SearchLog.response_time_ms)
        ).filter(
            SearchLog.created_at >= since_date
        ).scalar() or 0
        
        avg_result_count = db.query(
            func.avg(SearchLog.result_count)
        ).filter(
            SearchLog.created_at >= since_date
        ).scalar() or 0
        
        # Top queries
        top_queries = db.query(
            SearchLog.query, func.count(SearchLog.id)
        ).filter(
            SearchLog.created_at >= since_date
        ).group_by(
            SearchLog.query
        ).order_by(
            func.count(SearchLog.id).desc()
        ).limit(10).all()
        
        return {
            "total_searches": total_searches,
            "avg_response_time_ms": round(avg_response_time, 2),
            "avg_result_count": round(avg_result_count, 2),
            "top_queries": [{"query": q[0], "count": q[1]} for q in top_queries]
        }