from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, ForeignKey, JSON, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime

Base = declarative_base()


class CVE(Base):
    __tablename__ = "cves"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(20), unique=True, index=True, nullable=False)
    description = Column(Text, nullable=False)
    published_date = Column(DateTime, nullable=False)
    last_modified_date = Column(DateTime, nullable=False)
    severity = Column(String(10), nullable=False)
    cvss_score = Column(Float)
    cvss_vector = Column(String(100))
    attack_vector = Column(String(20))
    attack_complexity = Column(String(20))
    privileges_required = Column(String(20))
    user_interaction = Column(String(20))
    scope = Column(String(20))
    confidentiality_impact = Column(String(20))
    integrity_impact = Column(String(20))
    availability_impact = Column(String(20))
    source = Column(String(50), nullable=False)
    raw_data = Column(JSON)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    relationships = relationship("CVETag", back_populates="cve")
    affected_products = relationship("AffectedProduct", back_populates="cve")
    
    __table_args__ = (
        Index('idx_cve_severity', 'severity'),
        Index('idx_cve_cvss_score', 'cvss_score'),
        Index('idx_cve_published_date', 'published_date'),
    )


class Tag(Base):
    __tablename__ = "tags"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    category = Column(String(50), nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=func.now())
    
    relationships = relationship("CVETag", back_populates="tag")


class CVETag(Base):
    __tablename__ = "cve_tags"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(Integer, ForeignKey("cves.id"), nullable=False)
    tag_id = Column(Integer, ForeignKey("tags.id"), nullable=False)
    confidence = Column(Float, default=1.0)
    created_at = Column(DateTime, default=func.now())
    
    cve = relationship("CVE", back_populates="relationships")
    tag = relationship("Tag", back_populates="relationships")


class Vendor(Base):
    __tablename__ = "vendors"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=func.now())
    
    products = relationship("Product", back_populates="vendor")


class Product(Base):
    __tablename__ = "products"
    
    id = Column(Integer, primary_key=True, index=True)
    vendor_id = Column(Integer, ForeignKey("vendors.id"), nullable=False)
    name = Column(String(200), nullable=False)
    version = Column(String(100))
    created_at = Column(DateTime, default=func.now())
    
    vendor = relationship("Vendor", back_populates="products")
    affected_cves = relationship("AffectedProduct", back_populates="product")


class AffectedProduct(Base):
    __tablename__ = "affected_products"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(Integer, ForeignKey("cves.id"), nullable=False)
    product_id = Column(Integer, ForeignKey("products.id"), nullable=False)
    status = Column(String(20), nullable=False)
    action = Column(String(20))
    created_at = Column(DateTime, default=func.now())
    
    cve = relationship("CVE", back_populates="affected_products")
    product = relationship("Product", back_populates="affected_cves")


class Advisory(Base):
    __tablename__ = "advisories"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    source = Column(String(100), nullable=False)
    source_id = Column(String(100), nullable=False)
    url = Column(String(1000))
    published_date = Column(DateTime, nullable=False)
    last_modified_date = Column(DateTime)
    severity = Column(String(10))
    category = Column(String(50))
    affected_systems = Column(JSON)
    recommendations = Column(Text)
    raw_data = Column(JSON)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    relationships = relationship("AdvisoryCVE", back_populates="advisory")
    tags = relationship("AdvisoryTag", back_populates="advisory")
    
    __table_args__ = (
        Index('idx_advisory_source', 'source'),
        Index('idx_advisory_published_date', 'published_date'),
        Index('idx_advisory_severity', 'severity'),
    )


class AdvisoryCVE(Base):
    __tablename__ = "advisory_cves"
    
    id = Column(Integer, primary_key=True, index=True)
    advisory_id = Column(Integer, ForeignKey("advisories.id"), nullable=False)
    cve_id = Column(Integer, ForeignKey("cves.id"), nullable=False)
    created_at = Column(DateTime, default=func.now())
    
    advisory = relationship("Advisory", back_populates="relationships")
    cve = relationship("CVE")


class AdvisoryTag(Base):
    __tablename__ = "advisory_tags"
    
    id = Column(Integer, primary_key=True, index=True)
    advisory_id = Column(Integer, ForeignKey("advisories.id"), nullable=False)
    tag_id = Column(Integer, ForeignKey("tags.id"), nullable=False)
    created_at = Column(DateTime, default=func.now())
    
    advisory = relationship("Advisory", back_populates="tags")
    tag = relationship("Tag")


class VectorEmbedding(Base):
    __tablename__ = "vector_embeddings"
    
    id = Column(Integer, primary_key=True, index=True)
    content_type = Column(String(20), nullable=False)
    content_id = Column(Integer, nullable=False)
    embedding_model = Column(String(100), nullable=False)
    embedding = Column(JSON, nullable=False)
    text_content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=func.now())
    
    __table_args__ = (
        Index('idx_embedding_content', 'content_type', 'content_id'),
        Index('idx_embedding_model', 'embedding_model'),
    )


class SearchLog(Base):
    __tablename__ = "search_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    query = Column(Text, nullable=False)
    response_time_ms = Column(Integer)
    result_count = Column(Integer)
    user_ip = Column(String(45))
    user_agent = Column(Text)
    created_at = Column(DateTime, default=func.now())
    
    __table_args__ = (
        Index('idx_search_created_at', 'created_at'),
    )


class IngestionJob(Base):
    __tablename__ = "ingestion_jobs"
    
    id = Column(Integer, primary_key=True, index=True)
    job_type = Column(String(50), nullable=False)
    status = Column(String(20), nullable=False, default="pending")
    source = Column(String(100), nullable=False)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    items_processed = Column(Integer, default=0)
    items_failed = Column(Integer, default=0)
    error_message = Column(Text)
    job_metadata = Column(JSON)
    created_at = Column(DateTime, default=func.now())
    
    __table_args__ = (
        Index('idx_ingestion_status', 'status'),
        Index('idx_ingestion_job_type', 'job_type'),
        Index('idx_ingestion_created_at', 'created_at'),
    )