'use client';

import { useState } from 'react';
import { analyzeExtension, AnalysisResult } from '@/lib/analyzer';
import FileUploader from '@/components/FileUploader';
import AnalysisResults from '@/components/AnalysisResults';

export default function Home() {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleFileUpload = async (file: File) => {
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

  return (
    <main className="min-h-screen p-8 max-w-4xl mx-auto">
      <h1 className="text-4xl font-bold mb-8 text-center">CRX Security Checker</h1>

      <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow-md mb-8">
        <FileUploader onUpload={handleFileUpload} loading={loading} />
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
