import axios from 'axios';
import { SearchResult, SearchResponse } from '@/types/api';

// Use window.location to dynamically determine API URL, or fallback to same host on port 8000
const API_BASE_URL = typeof window !== 'undefined'
  ? `${window.location.protocol}//${window.location.hostname}:8000`
  : process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for error handling
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error:', error.response?.data || error.message);
    return Promise.reject(error);
  }
);

export interface SearchParams {
  query: string;
  limit?: number;
  severity_filter?: string[];
  date_range?: {
    start: string;
    end: string;
  };
  content_types?: string[];
}

export const searchApi = {
  // Search threat intelligence
  search: async (params: SearchParams): Promise<SearchResponse> => {
    const response = await apiClient.post('/api/search', params);
    return response.data;
  },

  // Get search suggestions
  getSuggestions: async (query: string): Promise<string[]> => {
    const response = await apiClient.get(`/api/search/suggestions?q=${encodeURIComponent(query)}`);
    return response.data;
  },

  // Get search statistics
  getStats: async (days: number = 30): Promise<any> => {
    const response = await apiClient.get(`/api/search/stats?days=${days}`);
    return response.data;
  },
};

export const cveApi = {
  // Get CVE by ID
  getCve: async (cveId: string): Promise<any> => {
    const response = await apiClient.get(`/api/cves/${cveId}`);
    return response.data;
  },

  // Get recent CVEs
  getRecent: async (limit: number = 10): Promise<any[]> => {
    const response = await apiClient.get(`/api/cves/recent?limit=${limit}`);
    return response.data;
  },

  // Get CVEs by severity
  getBySeverity: async (severity: string, limit: number = 20): Promise<any[]> => {
    const response = await apiClient.get(`/api/cves/severity/${severity}?limit=${limit}`);
    return response.data;
  },
};

export const advisoryApi = {
  // Get advisories
  getAdvisories: async (params: {
    source?: string;
    severity?: string;
    limit?: number;
  } = {}): Promise<any[]> => {
    const queryParams = new URLSearchParams();
    if (params.source) queryParams.append('source', params.source);
    if (params.severity) queryParams.append('severity', params.severity);
    if (params.limit) queryParams.append('limit', params.limit.toString());

    const response = await apiClient.get(`/api/advisories?${queryParams.toString()}`);
    return response.data;
  },

  // Get advisory by ID
  getAdvisory: async (id: number): Promise<any> => {
    const response = await apiClient.get(`/api/advisories/${id}`);
    return response.data;
  },
};

export const ingestionApi = {
  // Trigger manual ingestion
  triggerIngestion: async (type: 'cve' | 'advisory'): Promise<any> => {
    const response = await apiClient.post(`/api/ingestion/trigger/${type}`);
    return response.data;
  },

  // Get ingestion jobs
  getJobs: async (): Promise<any[]> => {
    const response = await apiClient.get('/api/ingestion/jobs');
    return response.data;
  },

  // Get ingestion stats
  getStats: async (): Promise<any> => {
    const response = await apiClient.get('/api/ingestion/stats');
    return response.data;
  },
};

export const healthApi = {
  // Health check
  check: async (): Promise<any> => {
    const response = await apiClient.get('/health');
    return response.data;
  },
};