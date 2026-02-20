import { Upload } from 'lucide-react';

interface FileUploaderProps {
  onUpload: (file: File) => void;
  loading: boolean;
}

export default function FileUploader({ onUpload, loading }: FileUploaderProps) {
  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      onUpload(file);
    }
  };

  return (
    <div className="flex flex-col items-center justify-center border-2 border-dashed border-zinc-300 dark:border-zinc-700 rounded-lg p-12 transition-colors hover:border-zinc-400 dark:hover:border-zinc-600">
      <Upload className="w-12 h-12 text-zinc-400 mb-4" />
      <p className="text-lg mb-4 text-zinc-600 dark:text-zinc-400">
        Upload a Chrome extension (.crx or .zip)
      </p>
      <input
        type="file"
        accept=".crx,.zip"
        onChange={handleChange}
        disabled={loading}
        className="hidden"
        id="file-upload"
      />
      <label
        htmlFor="file-upload"
        className={`px-6 py-2 bg-blue-600 text-white rounded-md cursor-pointer hover:bg-blue-700 transition-colors ${
          loading ? 'opacity-50 cursor-not-allowed' : ''
        }`}
      >
        {loading ? 'Analyzing...' : 'Select File'}
      </label>
    </div>
  );
}
