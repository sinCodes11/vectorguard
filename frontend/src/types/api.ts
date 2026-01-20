export interface SearchResult {
  content_type: 'cve' | 'advisory';
  content_id: number;
  title: string;
  description: string;
  relevance_score: number;
  metadata: {
    severity?: string;
    cvss_score?: number;
    published_date?: string;
    source?: string;
    attack_vector?: string;
    url?: string;
    [key: string]: any;
  };
}

export interface SearchResponse {
  query: string;
  results: SearchResult[];
  total_results: number;
  response_time_ms: number;
}

export interface CVE {
  id: number;
  cve_id: string;
  description: string;
  published_date: string;
  last_modified_date: string;
  severity: string;
  cvss_score?: number;
  cvss_vector?: string;
  attack_vector?: string;
  attack_complexity?: string;
  privileges_required?: string;
  user_interaction?: string;
  scope?: string;
  confidentiality_impact?: string;
  integrity_impact?: string;
  availability_impact?: string;
  source: string;
}

export interface Advisory {
  id: number;
  title: string;
  description: string;
  source: string;
  source_id: string;
  url?: string;
  published_date: string;
  last_modified_date?: string;
  severity?: string;
  category?: string;
  affected_systems?: string[];
  recommendations?: string;
}

export interface IngestionJob {
  id: number;
  job_type: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  source: string;
  started_at?: string;
  completed_at?: string;
  items_processed: number;
  items_failed: number;
  error_message?: string;
  created_at: string;
  metadata?: any;
}

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';