'use client';

import { useState } from 'react';
import { analyzeExtension, AnalysisResult } from '@/lib/analyzer';
import { extractExtensionId } from '@/lib/utils';
import Uploader from '@/components/Uploader';
import AnalysisResults from '@/components/AnalysisResults';

export default function Home() {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleFileUpload = async (file: File | Blob) => {
    setLoading(true);
    setError(null);
    try {
      const analysisResult = await analyzeExtension(file);
      setResult(analysisResult);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred during analysis');
    } finally {
      setLoading(false);
    }
  };

  const handleUrlSubmit = async (url: string) => {
    setLoading(true);
    setError(null);
    try {
      const extracted = extractExtensionId(url);
      if (!extracted) {
        throw new Error('Unsupported or invalid URL. Please use Chrome Web Store or Microsoft Edge Addons links.');
      }

      const { id, store, isRawId } = extracted;

      const performAnalysis = async (targetId: string, targetStore: 'chrome' | 'edge') => {
        // Fetch metadata and binary in parallel
        const [metaRes, binaryRes] = await Promise.all([
          fetch(`/api/proxy?id=${targetId}&store=${targetStore}&metadata=true`),
          fetch(`/api/proxy?id=${targetId}&store=${targetStore}`)
        ]);

        if (!binaryRes.ok) {
          const errorData = await binaryRes.json();
          throw new Error(errorData.error || 'Failed to download extension');
        }

        let metadata = null;
        if (metaRes.ok) {
          metadata = await metaRes.json();
        }

        const blob = await binaryRes.blob();
        if (blob.size === 0) {
          throw new Error('Extension download returned no content');
        }
        return await analyzeExtension(blob, metadata || undefined);
      };

      try {
        const analysisResult = await performAnalysis(id, store);
        setResult(analysisResult);
      } catch (err) {
        if (isRawId) {
          const alternateStore = store === 'edge' ? 'chrome' : 'edge';
          try {
            const analysisResult = await performAnalysis(id, alternateStore);
            setResult(analysisResult);
          } catch (secondErr) {
            throw err; // Throw the original error if both fail
          }
        } else {
          throw err;
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred during analysis');
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen p-8 max-w-4xl mx-auto">
      <h1 className="text-4xl font-bold mb-8 text-center">CRX Security Checker</h1>

      <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow-md mb-8">
        <Uploader onUpload={handleFileUpload} onUrlSubmit={handleUrlSubmit} loading={loading} />
      </div>

      {error && (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-8" role="alert">
          <span className="block sm:inline">{error}</span>
        </div>
      )}

      {result && <AnalysisResults result={result} />}
    </main>
  );
}
