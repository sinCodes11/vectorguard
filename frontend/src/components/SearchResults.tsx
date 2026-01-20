'use client';

import { SearchResponse, SearchResult } from '@/types/api';
import { Shield, FileText, ExternalLink, AlertTriangle, Info } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';

interface SearchResultsProps {
  searchResponse: SearchResponse | null;
}

export default function SearchResults({ searchResponse }: SearchResultsProps) {
  if (!searchResponse || searchResponse.results.length === 0) {
    return (
      <div className="text-center py-12">
        <div className="mx-auto h-24 w-24 text-gray-400 mb-4">
          <Info className="h-full w-full" />
        </div>
        <h3 className="text-lg font-medium text-gray-900 mb-2">No results found</h3>
        <p className="text-gray-600">
          Try adjusting your search terms or filters to find what you're looking for.
        </p>
      </div>
    );
  }

  const getSeverityColor = (severity: string) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-danger-100 text-danger-800 border-danger-200';
      case 'HIGH':
        return 'bg-warning-100 text-warning-800 border-warning-200';
      case 'MEDIUM':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'LOW':
        return 'bg-blue-100 text-blue-800 border-blue-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getCVSSColor = (score: number) => {
    if (score >= 9.0) return 'text-danger-600 bg-danger-50';
    if (score >= 7.0) return 'text-warning-600 bg-warning-50';
    if (score >= 4.0) return 'text-yellow-600 bg-yellow-50';
    return 'text-blue-600 bg-blue-50';
  };

  return (
    <div>
      {/* Search header */}
      <div className="mb-6 p-4 bg-gray-50 rounded-lg">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-gray-900">
              {searchResponse.total_results} results for "{searchResponse.query}"
            </h2>
            <p className="text-sm text-gray-600 mt-1">
              Found in {searchResponse.response_time_ms}ms
            </p>
          </div>
          <div className="text-sm text-gray-500">
            Relevance score applied
          </div>
        </div>
      </div>

      {/* Results list */}
      <div className="space-y-4">
        {searchResponse.results.map((result, index) => (
          <ResultCard key={`${result.content_type}-${result.content_id}-${index}`} result={result} />
        ))}
      </div>
    </div>
  );
}

function ResultCard({ result }: { result: SearchResult }) {
  const getSeverityColor = (severity: string) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-danger-100 text-danger-800 border-danger-200';
      case 'HIGH':
        return 'bg-warning-100 text-warning-800 border-warning-200';
      case 'MEDIUM':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'LOW':
        return 'bg-blue-100 text-blue-800 border-blue-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getCVSSColor = (score: number) => {
    if (score >= 9.0) return 'text-danger-600 bg-danger-50';
    if (score >= 7.0) return 'text-warning-600 bg-warning-50';
    if (score >= 4.0) return 'text-yellow-600 bg-yellow-50';
    return 'text-blue-600 bg-blue-50';
  };

  const formatPublishedDate = (dateString: string) => {
    try {
      const date = new Date(dateString);
      return formatDistanceToNow(date, { addSuffix: true });
    } catch {
      return dateString;
    }
  };

  return (
    <div className="bg-white border border-gray-200 rounded-lg p-6 hover:shadow-md transition-shadow">
      {/* Header */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center space-x-3">
          <div className={`p-2 rounded-lg ${
            result.content_type === 'cve' ? 'bg-red-50' : 'bg-blue-50'
          }`}>
            {result.content_type === 'cve' ? (
              <Shield className="h-5 w-5 text-red-600" />
            ) : (
              <FileText className="h-5 w-5 text-blue-600" />
            )}
          </div>
          <div>
            <h3 className="text-lg font-semibold text-gray-900">
              {result.title}
            </h3>
            <p className="text-sm text-gray-500">
              {result.content_type.toUpperCase()} • {result.metadata.source}
            </p>
          </div>
        </div>
        
        <div className="flex items-center space-x-2">
          {/* Severity badge */}
          {result.metadata.severity && (
            <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getSeverityColor(result.metadata.severity)}`}>
              {result.metadata.severity}
            </span>
          )}
          
          {/* Relevance score indicator */}
          <div className="text-right">
            <div className="text-xs text-gray-500">Relevance</div>
            <div className="text-sm font-medium text-primary-600">
              {Math.round(result.relevance_score * 100)}%
            </div>
          </div>
        </div>
      </div>

      {/* Description */}
      <p className="text-gray-700 mb-4 leading-relaxed">
        {result.description.length > 300 
          ? `${result.description.substring(0, 300)}...` 
          : result.description
        }
      </p>

      {/* Metadata */}
      <div className="flex flex-wrap items-center gap-4 text-sm">
        {/* CVSS Score for CVEs */}
        {result.metadata.cvss_score && (
          <div className="flex items-center space-x-2">
            <span className="text-gray-500">CVSS Score:</span>
            <span className={`px-2 py-1 rounded-md font-medium text-xs ${getCVSSColor(result.metadata.cvss_score)}`}>
              {result.metadata.cvss_score.toFixed(1)}
            </span>
          </div>
        )}

        {/* Published Date */}
        {result.metadata.published_date && (
          <div className="flex items-center space-x-2">
            <span className="text-gray-500">Published:</span>
            <span>{formatPublishedDate(result.metadata.published_date)}</span>
          </div>
        )}

        {/* Attack Vector for CVEs */}
        {result.metadata.attack_vector && (
          <div className="flex items-center space-x-2">
            <span className="text-gray-500">Attack Vector:</span>
            <span className="font-medium">{result.metadata.attack_vector}</span>
          </div>
        )}

        {/* URL for advisories */}
        {result.metadata.url && (
          <a
            href={result.metadata.url}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center space-x-1 text-primary-600 hover:text-primary-800 transition-colors"
          >
            <span>View Source</span>
            <ExternalLink className="h-4 w-4" />
          </a>
        )}
      </div>

      {/* Additional metadata indicator */}
      {Object.keys(result.metadata).length > 0 && (
        <div className="mt-3 pt-3 border-t border-gray-100">
          <div className="flex items-center text-xs text-gray-500">
            <Info className="h-3 w-3 mr-1" />
            Additional metadata available
          </div>
        </div>
      )}
    </div>
  );
}