import React, { useState } from 'react';
import { Upload, Link as LinkIcon, Plus } from 'lucide-react';

interface UploaderProps {
  onUpload: (file: File | Blob) => void;
  onUrlSubmit: (url: string) => void;
  loading: boolean;
}

export default function Uploader({ onUpload, onUrlSubmit, loading }: UploaderProps) {
  const [url, setUrl] = useState('');
  const [showFileUpload, setShowFileUpload] = useState(false);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      onUpload(file);
    }
  };

  const handleSubmitUrl = (e: React.FormEvent) => {
    e.preventDefault();
    if (url.trim()) {
      onUrlSubmit(url.trim());
    }
  };

  return (
    <div className="w-full space-y-4">
      <div className="flex gap-2">
        <form onSubmit={handleSubmitUrl} className="flex-1 flex gap-2">
          <div className="relative flex-1">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <LinkIcon className="h-5 w-5 text-zinc-400" />
            </div>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Paste Chrome or Edge store URL"
              className="block w-full pl-10 pr-3 py-2 border border-zinc-300 dark:border-zinc-700 rounded-md leading-5 bg-white dark:bg-zinc-800 placeholder-zinc-500 focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500 sm:text-sm transition-colors"
              disabled={loading}
            />
          </div>
          <button
            type="submit"
            disabled={loading || !url.trim()}
            className="px-6 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors whitespace-nowrap"
          >
            {loading ? 'Analyzing...' : 'Analyze URL'}
          </button>
        </form>

        <button
          onClick={() => setShowFileUpload(!showFileUpload)}
          className="p-2 border border-zinc-300 dark:border-zinc-700 rounded-md hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors"
          title="Upload CRX/ZIP file"
        >
          <Plus className={`w-6 h-6 text-zinc-600 dark:text-zinc-400 transition-transform ${showFileUpload ? 'rotate-45' : ''}`} />
        </button>
      </div>

      {showFileUpload && (
        <div className="p-8 border-2 border-dashed border-zinc-300 dark:border-zinc-700 rounded-lg flex flex-col items-center justify-center animate-in fade-in slide-in-from-top-2">
          <Upload className="w-10 h-10 text-zinc-400 mb-2" />
          <p className="text-sm text-zinc-600 dark:text-zinc-400 mb-4">
            Upload a Chrome extension (.crx or .zip)
          </p>
          <input
            type="file"
            accept=".crx,.zip"
            onChange={handleFileChange}
            disabled={loading}
            className="hidden"
            id="file-upload"
          />
          <label
            htmlFor="file-upload"
            className="px-4 py-2 bg-zinc-200 dark:bg-zinc-700 text-zinc-800 dark:text-zinc-200 rounded-md cursor-pointer hover:bg-zinc-300 dark:hover:bg-zinc-600 transition-colors"
          >
            Select File
          </label>
        </div>
      )}
    </div>
  );
}
