from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CVSSVector(str, Enum):
    NETWORK = "NETWORK"
    ADJACENT = "ADJACENT"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"


class IngestionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class CVEBase(BaseModel):
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$")
    description: str
    published_date: datetime
    last_modified_date: datetime
    severity: Severity
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    source: str


class CVEDetails(CVEBase):
    id: int
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    scope: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class CVECreate(CVEBase):
    pass


class CVEUpdate(BaseModel):
    description: Optional[str] = None
    severity: Optional[Severity] = None
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None


class TagBase(BaseModel):
    name: str
    category: str
    description: Optional[str] = None


class TagCreate(TagBase):
    pass


class Tag(TagBase):
    id: int
    created_at: datetime
    
    class Config:
        from_attributes = True


class VendorBase(BaseModel):
    name: str


class VendorCreate(VendorBase):
    pass


class Vendor(VendorBase):
    id: int
    created_at: datetime
    
    class Config:
        from_attributes = True


class ProductBase(BaseModel):
    vendor_id: int
    name: str
    version: Optional[str] = None


class ProductCreate(ProductBase):
    pass


class Product(ProductBase):
    id: int
    created_at: datetime
    vendor: Optional[Vendor] = None
    
    class Config:
        from_attributes = True


class AdvisoryBase(BaseModel):
    title: str
    description: str
    source: str
    source_id: str
    url: Optional[str] = None
    published_date: datetime
    last_modified_date: Optional[datetime] = None
    severity: Optional[Severity] = None
    category: Optional[str] = None
    affected_systems: Optional[List[str]] = None
    recommendations: Optional[str] = None


class AdvisoryCreate(AdvisoryBase):
    raw_data: Optional[Dict[str, Any]] = None


class Advisory(AdvisoryBase):
    id: int
    raw_data: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class SearchQuery(BaseModel):
    query: str = Field(..., min_length=1, max_length=1000)
    limit: int = Field(10, ge=1, le=100)
    severity_filter: Optional[List[Severity]] = None
    date_range: Optional[Dict[str, datetime]] = None
    content_types: Optional[List[str]] = None


class SearchResult(BaseModel):
    content_type: str
    content_id: int
    title: str
    description: str
    relevance_score: float
    metadata: Dict[str, Any]


class SearchResponse(BaseModel):
    query: str
    results: List[SearchResult]
    total_results: int
    response_time_ms: int


class IngestionJobBase(BaseModel):
    job_type: str
    source: str
    job_metadata: Optional[Dict[str, Any]] = None


class IngestionJobCreate(IngestionJobBase):
    pass


class IngestionJob(IngestionJobBase):
    id: int
    status: IngestionStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    items_processed: int = 0
    items_failed: int = 0
    error_message: Optional[str] = None
    created_at: datetime
    
    class Config:
        from_attributes = True


class ErrorResponse(BaseModel):
    error: str
    message: str
    details: Optional[Dict[str, Any]] = None


class HealthResponse(BaseModel):
    status: str
    timestamp: datetime
    version: str
    services: Dict[str, str]