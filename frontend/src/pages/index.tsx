'use client';

import { useState } from 'react';
import SearchBar from '@/components/SearchBar';
import SearchResults from '@/components/SearchResults';
import { SearchResponse } from '@/types/api';
import { Shield, TrendingUp, Database, Clock } from 'lucide-react';

export default function HomePage() {
  const [searchResponse, setSearchResponse] = useState<SearchResponse | null>(null);
  const [loading, setLoading] = useState(false);

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-primary-100 rounded-lg">
                <Shield className="h-6 w-6 text-primary-600" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900">VectorGuard</h1>
                <p className="text-xs text-gray-500">RAG-Powered Threat Intelligence</p>
              </div>
            </div>
            <nav className="hidden md:flex space-x-8">
              <a href="#search" className="text-gray-700 hover:text-primary-600 transition-colors">Search</a>
              <a href="#stats" className="text-gray-700 hover:text-primary-600 transition-colors">Analytics</a>
              <a href="#ingestion" className="text-gray-700 hover:text-primary-600 transition-colors">Data Sources</a>
            </nav>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="bg-gradient-to-br from-primary-50 to-indigo-100 py-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-4xl font-bold text-gray-900 mb-4">
            Threat Intelligence Knowledge Base
          </h2>
          <p className="text-xl text-gray-600 mb-8 max-w-3xl mx-auto">
            Search and analyze CVEs and security advisories with AI-powered natural language queries. 
            Get comprehensive threat intelligence data from multiple sources in real-time.
          </p>
          
          {/* Search Bar */}
          <SearchBar
            onSearch={setSearchResponse}
            loading={loading}
            setLoading={setLoading}
          />
        </div>
      </section>

      {/* Search Results Section */}
      {searchResponse && (
        <section id="search" className="py-8">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <SearchResults searchResponse={searchResponse} />
          </div>
        </section>
      )}

      {/* Features Section */}
      {!searchResponse && (
        <section className="py-16">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="text-center mb-12">
              <h2 className="text-3xl font-bold text-gray-900 mb-4">
                Advanced Threat Intelligence Platform
              </h2>
              <p className="text-lg text-gray-600 max-w-2xl mx-auto">
                Leveraging RAG technology to deliver comprehensive security insights
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
              <div className="text-center p-6 bg-white rounded-lg shadow-sm border border-gray-200">
                <div className="p-3 bg-primary-100 rounded-lg w-12 h-12 mx-auto mb-4">
                  <Database className="h-6 w-6 text-primary-600 mx-auto" />
                </div>
                <h3 className="font-semibold text-gray-900 mb-2">Real-time Ingestion</h3>
                <p className="text-sm text-gray-600">
                  Automated ingestion from NVD, CISA, US-CERT, and other security sources
                </p>
              </div>

              <div className="text-center p-6 bg-white rounded-lg shadow-sm border border-gray-200">
                <div className="p-3 bg-success-100 rounded-lg w-12 h-12 mx-auto mb-4">
                  <Shield className="h-6 w-6 text-success-600 mx-auto" />
                </div>
                <h3 className="font-semibold text-gray-900 mb-2">CVE Database</h3>
                <p className="text-sm text-gray-600">
                  Comprehensive vulnerability database with CVSS scores and analysis
                </p>
              </div>

              <div className="text-center p-6 bg-white rounded-lg shadow-sm border border-gray-200">
                <div className="p-3 bg-warning-100 rounded-lg w-12 h-12 mx-auto mb-4">
                  <TrendingUp className="h-6 w-6 text-warning-600 mx-auto" />
                </div>
                <h3 className="font-semibold text-gray-900 mb-2">AI-Powered Search</h3>
                <p className="text-sm text-gray-600">
                  Natural language queries with semantic understanding and relevance ranking
                </p>
              </div>

              <div className="text-center p-6 bg-white rounded-lg shadow-sm border border-gray-200">
                <div className="p-3 bg-blue-100 rounded-lg w-12 h-12 mx-auto mb-4">
                  <Clock className="h-6 w-6 text-blue-600 mx-auto" />
                </div>
                <h3 className="font-semibold text-gray-900 mb-2">Real-time Updates</h3>
                <p className="text-sm text-gray-600">
                  Continuous monitoring and ingestion of the latest threat intelligence
                </p>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* Stats Section */}
      {!searchResponse && (
        <section id="stats" className="bg-gray-100 py-16">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="text-center mb-12">
              <h2 className="text-3xl font-bold text-gray-900 mb-4">
                Platform Statistics
              </h2>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
              <div className="bg-white p-6 rounded-lg text-center">
                <div className="text-3xl font-bold text-primary-600 mb-2">200K+</div>
                <div className="text-sm text-gray-600">CVEs Indexed</div>
              </div>
              <div className="bg-white p-6 rounded-lg text-center">
                <div className="text-3xl font-bold text-success-600 mb-2">50K+</div>
                <div className="text-sm text-gray-600">Security Advisories</div>
              </div>
              <div className="bg-white p-6 rounded-lg text-center">
                <div className="text-3xl font-bold text-warning-600 mb-2">24/7</div>
                <div className="text-sm text-gray-600">Monitoring</div>
              </div>
              <div className="bg-white p-6 rounded-lg text-center">
                <div className="text-3xl font-bold text-blue-600 mb-2">&lt;100ms</div>
                <div className="text-sm text-gray-600">Query Time</div>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* Footer */}
      <footer className="bg-gray-900 text-white py-8">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <div className="flex items-center justify-center space-x-3 mb-4">
              <div className="p-2 bg-primary-100 rounded-lg">
                <Shield className="h-6 w-6 text-primary-600" />
              </div>
              <span className="text-xl font-bold">VectorGuard</span>
            </div>
            <p className="text-gray-400 text-sm">
              Self-hosted threat intelligence platform powered by RAG technology
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}