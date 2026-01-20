'use client';

import { useState } from 'react';
import { X, Calendar, Shield, FileText } from 'lucide-react';
import { SearchParams } from '@/services/api';

interface SearchFiltersProps {
  filters: SearchParams;
  setFilters: (filters: SearchParams) => void;
  onSearch: () => void;
}

export default function SearchFilters({ filters, setFilters, onSearch }: SearchFiltersProps) {
  const [dateRange, setDateRange] = useState({
    start: filters.date_range?.start || '',
    end: filters.date_range?.end || '',
  });

  const severityOptions = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const contentTypeOptions = [
    { value: 'cve', label: 'CVEs', icon: Shield },
    { value: 'advisory', label: 'Advisories', icon: FileText },
  ];

  const handleSeverityToggle = (severity: string) => {
    const currentSeverities = filters.severity_filter || [];
    const newSeverities = currentSeverities.includes(severity)
      ? currentSeverities.filter(s => s !== severity)
      : [...currentSeverities, severity];
    
    setFilters({ ...filters, severity_filter: newSeverities });
  };

  const handleContentTypeToggle = (contentType: string) => {
    const currentTypes = filters.content_types || [];
    const newTypes = currentTypes.includes(contentType)
      ? currentTypes.filter(t => t !== contentType)
      : [...currentTypes, contentType];
    
    setFilters({ ...filters, content_types: newTypes });
  };

  const handleDateRangeChange = (type: 'start' | 'end', value: string) => {
    const newDateRange = { ...dateRange, [type]: value };
    setDateRange(newDateRange);
    
    if (newDateRange.start && newDateRange.end) {
      setFilters({
        ...filters,
        date_range: {
          start: newDateRange.start,
          end: newDateRange.end,
        },
      });
    } else if (newDateRange.start || newDateRange.end) {
      // Partial date range - only set if both are filled
      setFilters({
        ...filters,
        date_range: undefined,
      });
    } else {
      const newFilters = { ...filters };
      delete newFilters.date_range;
      setFilters(newFilters);
    }
  };

  const clearFilters = () => {
    setFilters({
      query: filters.query,
      limit: filters.limit,
    });
    setDateRange({ start: '', end: '' });
  };

  return (
    <div className="absolute z-20 w-full mt-2 bg-white border border-gray-200 rounded-lg shadow-lg">
      <div className="p-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900">Search Filters</h3>
          <button
            onClick={() => setFilters({ ...filters })}
            className="text-gray-400 hover:text-gray-600"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Content Type Filter */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Content Type
            </label>
            <div className="space-y-2">
              {contentTypeOptions.map((option) => {
                const Icon = option.icon;
                const isSelected = (filters.content_types || []).includes(option.value);
                return (
                  <label
                    key={option.value}
                    className={`flex items-center p-3 rounded-lg border cursor-pointer transition-colors ${
                      isSelected
                        ? 'border-primary-500 bg-primary-50'
                        : 'border-gray-200 hover:bg-gray-50'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={() => handleContentTypeToggle(option.value)}
                      className="sr-only"
                    />
                    <Icon className="h-5 w-5 mr-3 text-gray-400" />
                    <span className="font-medium">{option.label}</span>
                  </label>
                );
              })}
            </div>
          </div>

          {/* Severity Filter */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Severity Level
            </label>
            <div className="space-y-2">
              {severityOptions.map((severity) => {
                const isSelected = (filters.severity_filter || []).includes(severity);
                const severityColors = {
                  CRITICAL: 'border-danger-500 bg-danger-50',
                  HIGH: 'border-warning-500 bg-warning-50',
                  MEDIUM: 'border-yellow-500 bg-yellow-50',
                  LOW: 'border-blue-500 bg-blue-50',
                };
                
                return (
                  <label
                    key={severity}
                    className={`flex items-center p-3 rounded-lg border cursor-pointer transition-colors ${
                      isSelected
                        ? severityColors[severity as keyof typeof severityColors]
                        : 'border-gray-200 hover:bg-gray-50'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={() => handleSeverityToggle(severity)}
                      className="sr-only"
                    />
                    <div className={`w-3 h-3 rounded-full mr-3 ${
                      severity === 'CRITICAL' ? 'bg-danger-500' :
                      severity === 'HIGH' ? 'bg-warning-500' :
                      severity === 'MEDIUM' ? 'bg-yellow-500' :
                      'bg-blue-500'
                    }`} />
                    <span className="font-medium">{severity}</span>
                  </label>
                );
              })}
            </div>
          </div>
        </div>

        {/* Date Range Filter */}
        <div className="mt-6">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            <Calendar className="inline h-4 w-4 mr-1" />
            Publication Date Range
          </label>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-gray-500 mb-1">Start Date</label>
              <input
                type="date"
                value={dateRange.start}
                onChange={(e) => handleDateRangeChange('start', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-primary-500 focus:border-primary-500"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-500 mb-1">End Date</label>
              <input
                type="date"
                value={dateRange.end}
                onChange={(e) => handleDateRangeChange('end', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-primary-500 focus:border-primary-500"
              />
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="flex justify-between items-center mt-6 pt-4 border-t border-gray-200">
          <button
            onClick={clearFilters}
            className="text-sm text-gray-500 hover:text-gray-700 transition-colors"
          >
            Clear all filters
          </button>
          <div className="space-x-3">
            <button
              onClick={() => setFilters({ ...filters })}
              className="px-4 py-2 text-gray-700 border border-gray-300 rounded-md hover:bg-gray-50 transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={onSearch}
              className="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 transition-colors"
            >
              Apply Filters
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}