import { AnalysisResult } from '@/lib/analyzer';
import { Shield, AlertTriangle, Info, Skull, Star, Users, Calendar, User, Code } from 'lucide-react';

interface AnalysisResultsProps {
  result: AnalysisResult;
}

export default function AnalysisResults({ result }: AnalysisResultsProps) {
  const ScoreGauge = ({ score, label, showInfo = false }: { score: number; label: string; showInfo?: boolean }) => {
    let colorClass = '';
    // For both Safety and Reputation: Higher is better
    // 0-25: Red (Critical)
    // 25-50: Orange (High)
    // 50-75: Yellow (Medium)
    // 75-100: Green (Low)
    if (score < 25) colorClass = 'text-red-500';
    else if (score < 50) colorClass = 'text-orange-500';
    else if (score < 75) colorClass = 'text-yellow-500';
    else colorClass = 'text-green-500';

    const strokeDasharray = `${(score / 100) * 251.2} 251.2`;

    return (
      <div className="flex flex-col items-center gap-1">
        <div className="relative w-20 h-20">
          <svg className="w-full h-full" viewBox="0 0 100 100">
            <circle cx="50" cy="50" r="40" fill="none" stroke="currentColor" strokeWidth="8" className="text-zinc-200 dark:text-zinc-700" />
            <circle
              cx="50" cy="50" r="40" fill="none" stroke="currentColor" strokeWidth="8"
              strokeDasharray={strokeDasharray}
              strokeLinecap="round"
              transform="rotate(-90 50 50)"
              className={`${colorClass} transition-all duration-500 ease-out`}
            />
            <text x="50" y="58" textAnchor="middle" className="text-xl font-bold fill-zinc-800 dark:fill-zinc-100">
              {Math.round(score)}
            </text>
          </svg>
        </div>
        <div className="flex items-center gap-1">
          <span className="text-[10px] font-bold uppercase tracking-wider text-zinc-500">{label}</span>
          {showInfo && <Info className="w-3 h-3 text-zinc-400" />}
        </div>
        <span className="text-[8px] text-zinc-400 -mt-1 italic">Higher is safer</span>
      </div>
    );
  };

  const getRiskIcon = (risk: string) => {
    switch (risk) {
      case 'Critical': return <Skull className="w-6 h-6 text-red-600" />;
      case 'High': return <AlertTriangle className="w-6 h-6 text-orange-600" />;
      case 'Medium': return <AlertTriangle className="w-6 h-6 text-yellow-600" />;
      case 'Low': return <Shield className="w-6 h-6 text-green-600" />;
      default: return <Info className="w-6 h-6 text-blue-600" />;
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'Critical': return 'text-red-600 bg-red-100';
      case 'High': return 'text-orange-600 bg-orange-100';
      case 'Medium': return 'text-yellow-600 bg-yellow-100';
      case 'Low': return 'text-green-600 bg-green-100';
      default: return 'text-blue-600 bg-blue-100';
    }
  };

  const getRiskLabelColor = (risk: string) => {
    switch (risk) {
      case 'Critical': return 'text-red-600';
      case 'High': return 'text-orange-600';
      case 'Medium': return 'text-yellow-600';
      case 'Low': return 'text-green-600';
      default: return 'text-blue-600';
    }
  };

  const getRelativeTime = (dateStr: string) => {
    const date = new Date(dateStr);
    if (isNaN(date.getTime())) return null;

    const now = new Date();
    const diffTime = Math.abs(now.getTime() - date.getTime());
    const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));

    if (diffDays < 1) return 'today';
    if (diffDays < 30) return `${diffDays} days ago`;
    const diffMonths = Math.floor(diffDays / 30);
    if (diffMonths < 12) return `${diffMonths} month${diffMonths > 1 ? 's' : ''} ago`;
    const diffYears = Math.floor(diffMonths / 12);
    return `${diffYears} year${diffYears > 1 ? 's' : ''} ago`;
  };

  return (
    <div className="space-y-8">
      <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow-md border-l-4 border-l-blue-500">
        <div className="flex flex-col md:flex-row justify-between gap-6">
          <div className="flex items-start gap-4 flex-1">
            {result.icon && (
              <img src={result.icon} alt={result.name} className="w-16 h-16 rounded-lg shadow-sm border border-zinc-200 dark:border-zinc-700" />
            )}
            <div>
              <h2 className="text-2xl font-bold mb-1">{result.name}</h2>
              <div className="flex flex-wrap gap-2 items-center mb-3">
                <p className="text-zinc-600 dark:text-zinc-400 text-sm">Version: {result.version}</p>
                <span className="px-2 py-0.5 bg-zinc-100 dark:bg-zinc-800 rounded text-[10px] font-bold text-zinc-500 uppercase">
                  Manifest V{result.manifestVersion}
                </span>
                {result.isObfuscated && (
                  <span className="px-2 py-0.5 bg-red-100 dark:bg-red-900/30 rounded text-[10px] font-bold text-red-600 uppercase flex items-center gap-1">
                    <Code className="w-3 h-3" /> Obfuscated
                  </span>
                )}
              </div>
              <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider ${getRiskColor(result.riskLevel)}`}>
                {result.riskLevel} Risk
              </span>
            </div>
          </div>

          <div className="flex gap-8">
            <div className="flex flex-col items-center gap-1 group relative">
              <ScoreGauge score={result.safetyScore} label="Safety Score" showInfo={true} />

              <div className="absolute z-20 hidden group-hover:block bg-zinc-800 text-white p-3 rounded-lg text-[10px] w-64 top-full left-1/2 -translate-x-1/2 mt-2 shadow-xl border border-zinc-700 pointer-events-none">
                <p className="font-bold mb-1 text-blue-400">Safety Score Calculation</p>
                <p className="font-mono mb-2 border-b border-zinc-700 pb-2">{result.riskEquation}</p>
                <div className="grid grid-cols-2 gap-x-4 gap-y-1 opacity-80">
                  <p>Permissions: Max 40</p>
                  <p>CVEs: 4 pts each (Max 20)</p>
                  <p>CVSS: Max 25</p>
                  <p>MV2 Penalty: 5 pts</p>
                  <p>Obfuscation: Max 10</p>
                </div>
              </div>
            </div>

            {result.reputationScore !== undefined && (
              <div className="flex flex-col items-center gap-1 group relative">
                <ScoreGauge score={result.reputationScore} label="Reputation Score" showInfo={true} />

                <div className="absolute z-20 hidden group-hover:block bg-zinc-800 text-white p-3 rounded-lg text-[10px] w-64 top-full left-1/2 -translate-x-1/2 mt-2 shadow-xl border border-zinc-700 pointer-events-none">
                  <p className="font-bold mb-1 text-blue-400">Reputation Score Calculation</p>
                  <p className="font-mono mb-2 border-b border-zinc-700 pb-2">{result.reputationEquation}</p>
                  <div className="grid grid-cols-2 gap-x-4 gap-y-1 opacity-80">
                    <p>Verified: 20 pts</p>
                    <p>Rating: Max 20 pts</p>
                    <p>Rating Count: Max 15 pts</p>
                    <p>User Count: Max 20 pts</p>
                    <p>Recency: Max 15 pts</p>
                    <p>Featured: 10 pts</p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {result.reputation && (
        <section className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow-md">
          <h3 className="text-xl font-semibold mb-6">Reputation</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
                <User className="w-5 h-5 text-blue-600" />
              </div>
              <div>
                <p className="text-xs text-zinc-500 font-medium uppercase tracking-wider">Publisher</p>
                <p className="font-semibold text-sm truncate max-w-[150px]" title={result.reputation.publisher}>{result.reputation.publisher || 'Unknown'}</p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <div className="p-2 bg-yellow-100 dark:bg-yellow-900/30 rounded-lg">
                <Star className="w-5 h-5 text-yellow-600" />
              </div>
              <div>
                <p className="text-xs text-zinc-500 font-medium uppercase tracking-wider">Rating</p>
                <p className="font-semibold text-sm">{result.reputation.rating} / 5 ({result.reputation.ratingCount})</p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <div className="p-2 bg-green-100 dark:bg-green-900/30 rounded-lg">
                <Users className="w-5 h-5 text-green-600" />
              </div>
              <div>
                <p className="text-xs text-zinc-500 font-medium uppercase tracking-wider">Users</p>
                <p className="font-semibold text-sm">{result.reputation.userCount}</p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <div className="p-2 bg-zinc-100 dark:bg-zinc-800 rounded-lg">
                <Calendar className="w-5 h-5 text-zinc-600" />
              </div>
              <div>
                <p className="text-xs text-zinc-500 font-medium uppercase tracking-wider">Last Updated</p>
                <p className="font-semibold text-sm">
                  {result.reputation.lastUpdated || 'Unknown'}
                  {getRelativeTime(result.reputation.lastUpdated) && (
                    <span className="block text-[10px] text-zinc-400 font-normal">
                      ({getRelativeTime(result.reputation.lastUpdated)})
                    </span>
                  )}
                </p>
              </div>
            </div>

            {(result.reputation.isFeatured || result.reputation.isVerifiedPublisher) && (
              <div className="flex items-center gap-3">
                <div className="p-2 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
                  <Shield className="w-5 h-5 text-purple-600" />
                </div>
                <div>
                  <p className="text-xs text-zinc-500 font-medium uppercase tracking-wider">Badges</p>
                  <div className="flex flex-wrap gap-1">
                    {result.reputation.isFeatured && (
                      <span className="text-[10px] font-bold text-purple-700 bg-purple-100 px-1 rounded">Featured</span>
                    )}
                    {result.reputation.isVerifiedPublisher && (
                      <span className="text-[10px] font-bold text-blue-700 bg-blue-100 px-1 rounded">Verified</span>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        </section>
      )}

      <section>
        <h3 className="text-xl font-semibold mb-4">Permissions</h3>
        <div className="grid gap-4">
          {result.permissions.length > 0 ? (
            result.permissions.map((p, idx) => (
              <div key={idx} className="bg-zinc-50 dark:bg-zinc-800 p-4 rounded-lg flex items-start gap-4">
                <div className="flex flex-col items-center gap-1 min-w-[60px]">
                  {getRiskIcon(p.risk)}
                  <span className={`text-[10px] font-bold uppercase ${getRiskLabelColor(p.risk)}`}>
                    {p.risk}
                  </span>
                </div>
                <div>
                  <p className="font-mono font-bold">{p.permission}</p>
                  <p className="text-sm text-zinc-600 dark:text-zinc-400">{p.description}</p>
                </div>
              </div>
            ))
          ) : (
            <p className="text-zinc-500 italic p-4 bg-zinc-50 dark:bg-zinc-800 rounded-lg text-center">No special permissions requested</p>
          )}
        </div>
      </section>

      <section>
        <h3 className="text-xl font-semibold mb-4">Vulnerabilities</h3>
        <div className="grid gap-4">
          {result.vulnerabilities.length > 0 ? (
            result.vulnerabilities.map((v, idx) => (
              <div key={idx} className="bg-red-50 dark:bg-red-900/20 p-4 rounded-lg border border-red-200 dark:border-red-800 flex items-start gap-4">
                {getRiskIcon(v.severity)}
                <div>
                  <p className="font-bold text-red-700 dark:text-red-400">
                    {v.id} ({v.severity}{v.score ? `: ${v.score}` : ''})
                  </p>
                  <p className="text-sm text-red-600 dark:text-red-300">{v.description}</p>
                </div>
              </div>
            ))
          ) : (
            <p className="text-zinc-500 italic p-4 bg-zinc-50 dark:bg-zinc-800 rounded-lg text-center">No known vulnerabilities detected</p>
          )}
        </div>
      </section>

      <section>
        <h3 className="text-xl font-semibold mb-4">Third-Party Libraries & API calls</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-4">
            <h4 className="text-sm font-bold uppercase tracking-wider text-zinc-500">Libraries</h4>
            <div className="flex flex-wrap gap-2">
              {result.dependencies.length > 0 ? (
                result.dependencies.map((dep, idx) => (
                  <span key={idx} className="px-3 py-1 bg-zinc-200 dark:bg-zinc-700 rounded-md text-sm">
                    {dep}
                  </span>
                ))
              ) : (
                <p className="text-zinc-500 italic text-sm">No third-party libraries identified</p>
              )}
            </div>
          </div>

          <div className="space-y-4">
            <h4 className="text-sm font-bold uppercase tracking-wider text-zinc-500">Sensitive API Calls</h4>
            <ul className="bg-zinc-50 dark:bg-zinc-800 p-3 rounded-lg space-y-1">
              {result.apiCalls.length > 0 ? (
                result.apiCalls.map((api, idx) => (
                  <li key={idx} className="font-mono text-xs">{api}</li>
                ))
              ) : (
                <p className="text-zinc-500 italic text-xs">No sensitive API calls detected</p>
              )}
            </ul>
          </div>
        </div>
      </section>

      <section>
        <h3 className="text-xl font-semibold mb-4">Obfuscation & Detected secrets</h3>
        <div className="space-y-6">
          <div className="bg-zinc-50 dark:bg-zinc-800 p-6 rounded-lg">
            <h4 className="text-sm font-bold uppercase tracking-wider text-zinc-500 mb-4 flex items-center gap-2">
              <Code className="w-4 h-4" /> Obfuscation Analysis
            </h4>
            {result.obfuscationTriggers.length > 0 ? (
              <div className="space-y-4">
                {result.obfuscationTriggers.map((trigger, idx) => (
                  <div key={idx} className="border-l-2 border-red-500 pl-4 py-1">
                    <p className="font-bold text-sm text-red-600 dark:text-red-400">{trigger.type}</p>
                    <p className="text-sm text-zinc-600 dark:text-zinc-400 mb-2">{trigger.description}</p>
                    <div className="flex flex-wrap gap-1">
                      {trigger.files.map((file, fidx) => (
                        <span key={fidx} className="text-[10px] font-mono bg-zinc-200 dark:bg-zinc-700 px-1.5 py-0.5 rounded">
                          {file}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-zinc-500 italic text-sm">No clear signs of obfuscation detected</p>
            )}
          </div>

          <div>
            <h4 className="text-sm font-bold uppercase tracking-wider text-zinc-500 mb-3">Detected Secrets</h4>
            <ul className="bg-zinc-50 dark:bg-zinc-800 p-4 rounded-lg space-y-2">
              {result.secrets.length > 0 ? (
                result.secrets.map((secret, idx) => (
                  <li key={idx} className="font-mono text-sm text-red-500">{secret}</li>
                ))
              ) : (
                <p className="text-zinc-500 italic text-sm">No secrets detected</p>
              )}
            </ul>
          </div>
        </div>
      </section>
    </div>
  );
}
