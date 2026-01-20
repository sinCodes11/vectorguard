import os
import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
import logging
from datetime import datetime
from src.models.database import CVE, Advisory, VectorEmbedding
from src.database.connection import get_db
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class EmbeddingService:
    def __init__(self):
        # Initialize the sentence transformer model
        model_name = os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
        self.model = SentenceTransformer(model_name)
        self.embedding_dimension = self.model.get_sentence_embedding_dimension()
        
        # Initialize ChromaDB
        persist_directory = os.getenv("CHROMA_PERSIST_DIRECTORY", "./chroma_data")
        self.chroma_client = chromadb.PersistentClient(
            path=persist_directory,
            settings=Settings(
                anonymized_telemetry=False
            )
        )
        
        # Get or create collections
        self.cve_collection = self.chroma_client.get_or_create_collection(
            name="cve_embeddings",
            metadata={"description": "CVE vulnerability embeddings"}
        )
        
        self.advisory_collection = self.chroma_client.get_or_create_collection(
            name="advisory_embeddings",
            metadata={"description": "Security advisory embeddings"}
        )
    
    def _prepare_cve_text(self, cve: CVE) -> str:
        """Prepare CVE text for embedding."""
        text_parts = [
            f"CVE ID: {cve.cve_id}",
            f"Description: {cve.description}",
            f"Severity: {cve.severity}",
            f"CVSS Score: {cve.cvss_score}" if cve.cvss_score else "",
        ]
        
        if cve.attack_vector:
            text_parts.append(f"Attack Vector: {cve.attack_vector}")
        if cve.attack_complexity:
            text_parts.append(f"Attack Complexity: {cve.attack_complexity}")
        
        return " ".join([part for part in text_parts if part])
    
    def _prepare_advisory_text(self, advisory: Advisory) -> str:
        """Prepare advisory text for embedding."""
        text_parts = [
            f"Title: {advisory.title}",
            f"Description: {advisory.description}",
            f"Source: {advisory.source}",
            f"Severity: {advisory.severity}" if advisory.severity else "",
        ]
        
        if advisory.category:
            text_parts.append(f"Category: {advisory.category}")
        if advisory.recommendations:
            text_parts.append(f"Recommendations: {advisory.recommendations}")
        
        return " ".join([part for part in text_parts if part])
    
    def generate_embedding(self, text: str) -> List[float]:
        """Generate embedding for a given text."""
        try:
            embedding = self.model.encode(text, convert_to_numpy=True)
            return embedding.tolist()
        except Exception as e:
            logger.error(f"Error generating embedding: {e}")
            # Return zero embedding as fallback
            return [0.0] * self.embedding_dimension
    
    async def embed_cve(self, db: Session, cve: CVE) -> bool:
        """Generate and store embedding for a CVE."""
        
        try:
            text = self._prepare_cve_text(cve)
            embedding = self.generate_embedding(text)
            
            # Store in ChromaDB
            self.cve_collection.add(
                embeddings=[embedding],
                documents=[text],
                metadatas=[{
                    "cve_id": cve.cve_id,
                    "severity": cve.severity,
                    "cvss_score": cve.cvss_score,
                    "source": cve.source
                }],
                ids=[f"cve_{cve.id}"]
            )
            
            # Store in database
            vector_embedding = VectorEmbedding(
                content_type="cve",
                content_id=cve.id,
                embedding_model=os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2"),
                embedding=embedding,
                text_content=text
            )
            db.add(vector_embedding)
            
            return True
            
        except Exception as e:
            logger.error(f"Error embedding CVE {cve.cve_id}: {e}")
            return False
    
    async def embed_advisory(self, db: Session, advisory: Advisory) -> bool:
        """Generate and store embedding for an advisory."""
        
        try:
            text = self._prepare_advisory_text(advisory)
            embedding = self.generate_embedding(text)
            
            # Store in ChromaDB
            self.advisory_collection.add(
                embeddings=[embedding],
                documents=[text],
                metadatas=[{
                    "advisory_id": advisory.id,
                    "source": advisory.source,
                    "severity": advisory.severity,
                    "published_date": advisory.published_date.isoformat()
                }],
                ids=[f"advisory_{advisory.id}"]
            )
            
            # Store in database
            vector_embedding = VectorEmbedding(
                content_type="advisory",
                content_id=advisory.id,
                embedding_model=os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2"),
                embedding=embedding,
                text_content=text
            )
            db.add(vector_embedding)
            
            return True
            
        except Exception as e:
            logger.error(f"Error embedding advisory {advisory.id}: {e}")
            return False
    
    async def generate_embeddings_for_new_content(self, db: Session) -> Dict[str, int]:
        """Generate embeddings for content that doesn't have them yet."""
        
        processed = 0
        failed = 0
        
        # Find CVEs without embeddings
        cves_without_embeddings = db.query(CVE).filter(
            ~CVE.id.in_(
                db.query(VectorEmbedding.content_id).filter(
                    VectorEmbedding.content_type == "cve"
                )
            )
        ).limit(1000).all()  # Process in batches
        
        for cve in cves_without_embeddings:
            if await self.embed_cve(db, cve):
                processed += 1
            else:
                failed += 1
        
        # Find advisories without embeddings
        advisories_without_embeddings = db.query(Advisory).filter(
            ~Advisory.id.in_(
                db.query(VectorEmbedding.content_id).filter(
                    VectorEmbedding.content_type == "advisory"
                )
            )
        ).limit(1000).all()
        
        for advisory in advisories_without_embeddings:
            if await self.embed_advisory(db, advisory):
                processed += 1
            else:
                failed += 1
        
        try:
            db.commit()
            logger.info(f"Embedding generation completed: {processed} processed, {failed} failed")
        except Exception as e:
            logger.error(f"Error committing embeddings: {e}")
            db.rollback()
        
        return {"processed": processed, "failed": failed}
    
    def search_similar_cves(self, query: str, n_results: int = 10) -> List[Dict[str, Any]]:
        """Search for similar CVEs using vector similarity."""
        
        try:
            query_embedding = self.generate_embedding(query)
            
            results = self.cve_collection.query(
                query_embeddings=[query_embedding],
                n_results=n_results,
                include=["documents", "metadatas", "distances"]
            )
            
            search_results = []
            for i in range(len(results["ids"][0])):
                search_results.append({
                    "id": results["ids"][0][i],
                    "document": results["documents"][0][i],
                    "metadata": results["metadatas"][0][i],
                    "distance": results["distances"][0][i],
                    "similarity": 1 - results["distances"][0][i]  # Convert distance to similarity
                })
            
            return search_results
            
        except Exception as e:
            logger.error(f"Error searching CVEs: {e}")
            return []
    
    def search_similar_advisories(self, query: str, n_results: int = 10) -> List[Dict[str, Any]]:
        """Search for similar advisories using vector similarity."""
        
        try:
            query_embedding = self.generate_embedding(query)
            
            results = self.advisory_collection.query(
                query_embeddings=[query_embedding],
                n_results=n_results,
                include=["documents", "metadatas", "distances"]
            )
            
            search_results = []
            for i in range(len(results["ids"][0])):
                search_results.append({
                    "id": results["ids"][0][i],
                    "document": results["documents"][0][i],
                    "metadata": results["metadatas"][0][i],
                    "distance": results["distances"][0][i],
                    "similarity": 1 - results["distances"][0][i]
                })
            
            return search_results
            
        except Exception as e:
            logger.error(f"Error searching advisories: {e}")
            return []
    
    def hybrid_search(self, query: str, 
                     content_types: List[str] = None,
                     n_results: int = 20) -> Dict[str, List[Dict[str, Any]]]:
        """Perform hybrid search across multiple content types."""
        
        if content_types is None:
            content_types = ["cve", "advisory"]
        
        results = {}
        
        if "cve" in content_types:
            results["cve"] = self.search_similar_cves(query, n_results // 2)
        
        if "advisory" in content_types:
            results["advisory"] = self.search_similar_advisories(query, n_results // 2)
        
        return results
    
    def get_embedding_stats(self) -> Dict[str, Any]:
        """Get statistics about the embeddings."""
        
        cve_count = self.cve_collection.count()
        advisory_count = self.advisory_collection.count()
        
        return {
            "total_cve_embeddings": cve_count,
            "total_advisory_embeddings": advisory_count,
            "total_embeddings": cve_count + advisory_count,
            "embedding_model": os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2"),
            "embedding_dimension": self.embedding_dimension
        }
    
    async def delete_embeddings_by_content_type(self, content_type: str, content_id: int):
        """Delete embeddings for specific content."""
        
        try:
            if content_type == "cve":
                self.cve_collection.delete(ids=[f"cve_{content_id}"])
            elif content_type == "advisory":
                self.advisory_collection.delete(ids=[f"advisory_{content_id}"])
            
            # Also delete from database
            db = next(get_db())
            db.query(VectorEmbedding).filter(
                VectorEmbedding.content_type == content_type,
                VectorEmbedding.content_id == content_id
            ).delete()
            db.commit()
            db.close()
            
        except Exception as e:
            logger.error(f"Error deleting embeddings: {e}")