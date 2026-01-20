'use client';

import { useState, useCallback, useRef, useEffect } from 'react';
import { Search, X, Filter, Clock, TrendingUp } from 'lucide-react';
import { searchApi, SearchParams } from '@/services/api';
import { SearchResponse, SearchResult } from '@/types/api';
import SearchResults from './SearchResults';
import SearchFilters from './SearchFilters';

interface SearchBarProps {
  onSearch: (results: SearchResponse) => void;
  loading: boolean;
  setLoading: (loading: boolean) => void;
}

export default function SearchBar({ onSearch, loading, setLoading }: SearchBarProps) {
  const [query, setQuery] = useState('');
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [showFilters, setShowFilters] = useState(false);
  const [filters, setFilters] = useState<SearchParams>({
    query: '',
    limit: 20,
    severity_filter: [],
    content_types: ['cve', 'advisory'],
  });
  
  const searchRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleSearch = useCallback(async (searchQuery?: string) => {
    const finalQuery = searchQuery || query;
    
    if (!finalQuery.trim()) return;
    
    setLoading(true);
    setSuggestions([]);
    setShowSuggestions(false);

    try {
      const searchParams: SearchParams = {
        ...filters,
        query: finalQuery,
      };
      
      const response = await searchApi.search(searchParams);
      onSearch(response);
    } catch (error) {
      console.error('Search failed:', error);
      // Could add error handling/notification here
    } finally {
      setLoading(false);
    }
  }, [query, filters, onSearch, setLoading]);

  const fetchSuggestions = useCallback(async (value: string) => {
    if (value.length < 2) {
      setSuggestions([]);
      return;
    }

    try {
      const suggestions = await searchApi.getSuggestions(value);
      setSuggestions(suggestions);
      setShowSuggestions(true);
    } catch (error) {
      console.error('Failed to fetch suggestions:', error);
    }
  }, []);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setQuery(value);
    setFilters({ ...filters, query: value });
    
    if (value.length >= 2) {
      fetchSuggestions(value);
    } else {
      setSuggestions([]);
      setShowSuggestions(false);
    }
  };

  const handleSuggestionClick = (suggestion: string) => {
    setQuery(suggestion);
    setFilters({ ...filters, query: suggestion });
    setShowSuggestions(false);
    handleSearch(suggestion);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleSearch();
    } else if (e.key === 'Escape') {
      setShowSuggestions(false);
      setShowFilters(false);
    }
  };

  const clearSearch = () => {
    setQuery('');
    setFilters({ ...filters, query: '' });
    setSuggestions([]);
    setShowSuggestions(false);
    inputRef.current?.focus();
  };

  // Click outside to close suggestions/filters
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (searchRef.current && !searchRef.current.contains(event.target as Node)) {
        setShowSuggestions(false);
        setShowFilters(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <div className="w-full max-w-4xl mx-auto" ref={searchRef}>
      <div className="relative">
        {/* Main search input */}
        <div className="relative flex items-center">
          <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
            <Search className="h-5 w-5 text-gray-400" />
          </div>
          
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={handleInputChange}
            onKeyDown={handleKeyDown}
            onFocus={() => query.length >= 2 && setShowSuggestions(true)}
            placeholder="Search for CVEs, security advisories, or threats..."
            className="w-full pl-12 pr-24 py-4 text-lg border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-transparent shadow-sm"
            disabled={loading}
          />
          
          <div className="absolute inset-y-0 right-0 flex items-center space-x-2 pr-4">
            {query && (
              <button
                onClick={clearSearch}
                className="p-1 text-gray-400 hover:text-gray-600 transition-colors"
                title="Clear search"
              >
                <X className="h-5 w-5" />
              </button>
            )}
            
            <button
              onClick={() => setShowFilters(!showFilters)}
              className={`p-2 rounded-md transition-colors ${
                showFilters 
                  ? 'bg-primary-100 text-primary-700' 
                  : 'text-gray-400 hover:text-gray-600'
              }`}
              title="Toggle filters"
            >
              <Filter className="h-5 w-5" />
            </button>
            
            <button
              onClick={() => handleSearch()}
              disabled={loading || !query.trim()}
              className="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {loading ? (
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
              ) : (
                'Search'
              )}
            </button>
          </div>
        </div>

        {/* Suggestions dropdown */}
        {showSuggestions && suggestions.length > 0 && (
          <div className="absolute z-10 w-full mt-2 bg-white border border-gray-200 rounded-md shadow-lg">
            <ul className="max-h-60 overflow-auto py-1">
              {suggestions.map((suggestion, index) => (
                <li key={index}>
                  <button
                    onClick={() => handleSuggestionClick(suggestion)}
                    className="w-full px-4 py-2 text-left hover:bg-gray-50 transition-colors"
                  >
                    <Search className="inline h-4 w-4 mr-2 text-gray-400" />
                    {suggestion}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Filters panel */}
        {showFilters && (
          <SearchFilters
            filters={filters}
            setFilters={setFilters}
            onSearch={handleSearch}
          />
        )}
      </div>

      {/* Quick search hints */}
      {query.length === 0 && !showFilters && (
        <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="text-center p-4 bg-gray-50 rounded-lg">
            <Clock className="h-8 w-8 mx-auto mb-2 text-gray-400" />
            <h3 className="font-medium text-gray-900 mb-1">Recent Threats</h3>
            <p className="text-sm text-gray-600">Try "latest CVEs" or "recent advisories"</p>
          </div>
          <div className="text-center p-4 bg-gray-50 rounded-lg">
            <TrendingUp className="h-8 w-8 mx-auto mb-2 text-gray-400" />
            <h3 className="font-medium text-gray-900 mb-1">By Severity</h3>
            <p className="text-sm text-gray-600">Try "critical vulnerabilities" or "high severity"</p>
          </div>
          <div className="text-center p-4 bg-gray-50 rounded-lg">
            <Search className="h-8 w-8 mx-auto mb-2 text-gray-400" />
            <h3 className="font-medium text-gray-900 mb-1">Specific CVEs</h3>
            <p className="text-sm text-gray-600">Try "CVE-2024-0001" or specific vulnerability names</p>
          </div>
        </div>
      )}
    </div>
  );
}