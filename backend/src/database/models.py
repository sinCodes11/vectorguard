from sqlalchemy import Column, String, DateTime, Float
from src.database.database import Base

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    cve_id = Column(String, primary_key=True, index=True)
    description = Column(String)
    published_date = Column(DateTime)
    last_modified_date = Column(DateTime)
    severity = Column(String)
    vector_string = Column(String)

    def __repr__(self):
        return f"<Vulnerability(cve_id='{self.cve_id}', severity='{self.severity}')>"
