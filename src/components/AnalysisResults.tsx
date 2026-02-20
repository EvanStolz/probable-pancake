import { AnalysisResult } from '@/lib/analyzer';
import { Shield, AlertTriangle, Info, Skull } from 'lucide-react';

interface AnalysisResultsProps {
  result: AnalysisResult;
}

export default function AnalysisResults({ result }: AnalysisResultsProps) {
  const getRiskIcon = (risk: string) => {
    switch (risk) {
      case 'Critical': return <Skull className="w-6 h-6 text-purple-600" />;
      case 'High': return <AlertTriangle className="w-6 h-6 text-red-600" />;
      case 'Medium': return <AlertTriangle className="w-6 h-6 text-yellow-600" />;
      case 'Low': return <Shield className="w-6 h-6 text-green-600" />;
      default: return <Info className="w-6 h-6 text-blue-600" />;
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'Critical': return 'text-purple-600 bg-purple-100';
      case 'High': return 'text-red-600 bg-red-100';
      case 'Medium': return 'text-yellow-600 bg-yellow-100';
      case 'Low': return 'text-green-600 bg-green-100';
      default: return 'text-blue-600 bg-blue-100';
    }
  };

  return (
    <div className="space-y-8">
      <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow-md border-l-4 border-l-blue-500">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-2xl font-bold">{result.name}</h2>
          <span className={`px-4 py-1 rounded-full font-semibold ${getRiskColor(result.riskLevel)}`}>
            {result.riskLevel} Risk (CVSS: {result.cvssScore})
          </span>
        </div>
        <p className="text-zinc-600 dark:text-zinc-400">Version: {result.version}</p>
      </div>

      <section>
        <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
          Permissions
        </h3>
        <div className="grid gap-4">
          {result.permissions.map((p, idx) => (
            <div key={idx} className="bg-zinc-50 dark:bg-zinc-800 p-4 rounded-lg flex items-start gap-4">
              {getRiskIcon(p.risk)}
              <div>
                <p className="font-mono font-bold">{p.permission}</p>
                <p className="text-sm text-zinc-600 dark:text-zinc-400">{p.description}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        <section>
          <h3 className="text-xl font-semibold mb-4">API Calls</h3>
          <ul className="bg-zinc-50 dark:bg-zinc-800 p-4 rounded-lg space-y-2">
            {result.apiCalls.length > 0 ? (
              result.apiCalls.map((api, idx) => (
                <li key={idx} className="font-mono text-sm">{api}</li>
              ))
            ) : (
              <p className="text-zinc-500 italic">No sensitive API calls detected</p>
            )}
          </ul>
        </section>

        <section>
          <h3 className="text-xl font-semibold mb-4">Detected Secrets</h3>
          <ul className="bg-zinc-50 dark:bg-zinc-800 p-4 rounded-lg space-y-2">
            {result.secrets.length > 0 ? (
              result.secrets.map((secret, idx) => (
                <li key={idx} className="font-mono text-sm text-red-500">{secret}</li>
              ))
            ) : (
              <p className="text-zinc-500 italic">No secrets detected</p>
            )}
          </ul>
        </section>
      </div>

      <section>
        <h3 className="text-xl font-semibold mb-4">Third-party Libraries & Vulnerabilities</h3>
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2">
            {result.dependencies.length > 0 ? (
              result.dependencies.map((dep, idx) => (
                <span key={idx} className="px-3 py-1 bg-zinc-200 dark:bg-zinc-700 rounded-md text-sm">
                  {dep}
                </span>
              ))
            ) : (
              <p className="text-zinc-500 italic">No third-party libraries identified</p>
            )}
          </div>

          {result.vulnerabilities.length > 0 && (
            <div className="grid gap-4 mt-4">
              {result.vulnerabilities.map((v, idx) => (
                <div key={idx} className="bg-red-50 dark:bg-red-900/20 p-4 rounded-lg border border-red-200 dark:border-red-800 flex items-start gap-4">
                  {getRiskIcon(v.severity)}
                  <div>
                    <p className="font-bold text-red-700 dark:text-red-400">{v.id} ({v.severity})</p>
                    <p className="text-sm text-red-600 dark:text-red-300">{v.description}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
