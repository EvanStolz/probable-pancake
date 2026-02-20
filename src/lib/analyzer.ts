import JSZip from 'jszip';

export interface PermissionInfo {
  permission: string;
  risk: 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
}

export interface Vulnerability {
  id: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
  score?: number;
}

export interface ReputationData {
  publisher: string;
  rating: number;
  ratingCount: number;
  userCount: string;
  lastUpdated: string;
}

export interface AnalysisResult {
  name: string;
  version: string;
  icon?: string;
  permissions: PermissionInfo[];
  apiCalls: string[];
  secrets: string[];
  dependencies: string[];
  vulnerabilities: Vulnerability[];
  cvssScore: number;
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  riskScore: number;
  riskEquation: string;
  reputation?: ReputationData;
  reputationScore?: number;
}

export async function analyzeExtension(
  file: File | Blob | ArrayBuffer | Uint8Array,
  externalReputation?: ReputationData
): Promise<AnalysisResult> {
  let data: ArrayBuffer;
  if (file instanceof File || file instanceof Blob) {
    data = await file.arrayBuffer();
  } else if (file instanceof Uint8Array) {
    data = file.buffer.slice(file.byteOffset, file.byteOffset + file.byteLength);
  } else {
    data = file;
  }

  // Handle CRX files (they have a header before the ZIP content)
  const view = new DataView(data);
  if (view.byteLength > 4 && view.getUint32(0, true) === 0x34327243) { // 'Cr24'
    const version = view.getUint32(4, true);
    let offset = 0;
    if (version === 2) {
      const publicKeyLength = view.getUint32(8, true);
      const signatureLength = view.getUint32(12, true);
      offset = 16 + publicKeyLength + signatureLength;
    } else if (version === 3) {
      const headerLength = view.getUint32(8, true);
      offset = 12 + headerLength;
    }

    if (offset > 0 && offset < data.byteLength) {
      data = data.slice(offset);
    }
  }

  const zip = await JSZip.loadAsync(data);
  const manifestFile = zip.file('manifest.json');

  if (!manifestFile) {
    throw new Error('manifest.json not found in extension');
  }

  const manifestContent = await manifestFile.async('string');
  const manifest = JSON.parse(manifestContent);

  // Resolve localized name
  let name = manifest.name || 'Unknown';
  if (name.startsWith('__MSG_')) {
    name = await resolveLocaleString(zip, manifest, name);
  }

  // Extract icon
  let icon: string | undefined;
  if (manifest.icons) {
    const iconPath = manifest.icons['48'] || manifest.icons['128'] || manifest.icons['16'];
    if (iconPath) {
      const iconFile = zip.file(iconPath);
      if (iconFile) {
        const iconData = await iconFile.async('base64');
        const mimeType = iconPath.endsWith('.png') ? 'image/png' : 'image/jpeg';
        icon = `data:${mimeType};base64,${iconData}`;
      }
    }
  }

  const permissions = analyzePermissions(manifest.permissions || [], manifest.host_permissions || []);
  const { apiCalls, secrets, dependencies } = await analyzeSourceCode(zip);
  const vulnerabilities = detectVulnerabilities(dependencies);

  const { score: cvssScore, equation: riskEquation } = calculateDetailedRisk(permissions, apiCalls, vulnerabilities);
  const riskLevel = getOverallRiskLevel(cvssScore);
  const riskScore = Math.max(0, Math.round((10 - cvssScore) * 10));

  let reputationScore: number | undefined;
  if (externalReputation) {
    reputationScore = calculateReputationScore(externalReputation);
  }

  return {
    name,
    version: manifest.version || '0.0.0',
    icon,
    permissions,
    apiCalls,
    secrets,
    dependencies,
    vulnerabilities,
    cvssScore,
    riskLevel,
    riskScore,
    riskEquation,
    reputation: externalReputation,
    reputationScore,
  };
}

async function resolveLocaleString(zip: JSZip, manifest: any, key: string): Promise<string> {
  const messageKey = key.replace('__MSG_', '').replace('__', '');
  const defaultLocale = manifest.default_locale || 'en';

  // Try default locale first, then look for any locale if not found
  const locales = [defaultLocale, 'en', 'en_US', 'en_GB'];

  for (const locale of locales) {
    const localePath = `_locales/${locale}/messages.json`;
    const localeFile = zip.file(localePath);
    if (localeFile) {
      try {
        const content = await localeFile.async('string');
        const messages = JSON.parse(content);
        if (messages[messageKey] && messages[messageKey].message) {
          return messages[messageKey].message;
        }
      } catch (e) {
        // Ignore parse errors
      }
    }
  }

  // Last ditch effort: search all locales
  const localeFiles = zip.filter((path) => path.startsWith('_locales/') && path.endsWith('messages.json'));
  for (const file of localeFiles) {
    try {
      const content = await file.async('string');
      const messages = JSON.parse(content);
      if (messages[messageKey] && messages[messageKey].message) {
        return messages[messageKey].message;
      }
    } catch (e) {}
  }

  return key; // Fallback to original key if not found
}

const PERMISSION_MAPPING: Record<string, { risk: 'Low' | 'Medium' | 'High' | 'Critical', description: string }> = {
  'activeTab': { risk: 'Low', description: 'Access the current tab when the user interacts with the extension.' },
  'alarms': { risk: 'Low', description: 'Schedule code to run at specific times.' },
  'bookmarks': { risk: 'Medium', description: 'Read and modify browser bookmarks.' },
  'browsingData': { risk: 'High', description: 'Clear browsing data like cookies and history.' },
  'clipboardRead': { risk: 'High', description: 'Read data from the clipboard.' },
  'clipboardWrite': { risk: 'Medium', description: 'Write data to the clipboard.' },
  'cookies': { risk: 'High', description: 'Access and modify cookies for any website.' },
  'debugger': { risk: 'Critical', description: 'Use the browser debugger protocol, which allows full control over the browser.' },
  'desktopCapture': { risk: 'High', description: 'Capture screenshots of the desktop.' },
  'downloads': { risk: 'Medium', description: 'Manage browser downloads.' },
  'geolocation': { risk: 'Medium', description: 'Access the user\'s physical location.' },
  'history': { risk: 'High', description: 'Read and modify the browser\'s history.' },
  'identity': { risk: 'Medium', description: 'Access the user\'s Google account identity.' },
  'management': { risk: 'High', description: 'Manage other installed extensions and apps.' },
  'notifications': { risk: 'Low', description: 'Display desktop notifications.' },
  'proxy': { risk: 'High', description: 'Manage the browser\'s proxy settings.' },
  'sessions': { risk: 'High', description: 'Enumerate and restore open tabs and windows.' },
  'storage': { risk: 'Low', description: 'Store and retrieve data locally.' },
  'tabGroups': { risk: 'Low', description: 'Manage tab groups.' },
  'tabs': { risk: 'Medium', description: 'Access tab metadata like URL and title.' },
  'topSites': { risk: 'Low', description: 'Access the list of the user\'s most visited websites.' },
  'webNavigation': { risk: 'Medium', description: 'Receive notifications about the status of navigation requests.' },
  'webRequest': { risk: 'High', description: 'Intercept, block, or modify network requests.' },
  'webRequestBlocking': { risk: 'High', description: 'Block or modify network requests (requires webRequest).' },
  '<all_urls>': { risk: 'Critical', description: 'Full access to all websites the user visits.' },
};

function analyzePermissions(permissions: string[], hostPermissions: string[]): PermissionInfo[] {
  const allPermissions = [...new Set([...permissions, ...hostPermissions])];

  return allPermissions.map(p => {
    if (PERMISSION_MAPPING[p]) {
      return {
        permission: p,
        risk: PERMISSION_MAPPING[p].risk,
        description: PERMISSION_MAPPING[p].description,
      };
    }

    // Check for URL patterns in host permissions
    if (p.includes('://') || p === '<all_urls>') {
      return {
        permission: p,
        risk: p === '<all_urls>' ? 'Critical' : 'High',
        description: `Access to data on ${p === '<all_urls>' ? 'all websites' : p}.`,
      };
    }

    return {
      permission: p,
      risk: 'Low',
      description: 'Standard extension permission.',
    };
  });
}

async function analyzeSourceCode(zip: JSZip): Promise<{ apiCalls: string[], secrets: string[], dependencies: string[] }> {
  const apiCallsSet = new Set<string>();
  const secretsSet = new Set<string>();
  const dependenciesSet = new Set<string>();

  const API_PATTERNS = [
    /chrome\.\w+/g,
    /browser\.\w+/g,
    /fetch\s*\(/g,
    /XMLHttpRequest/g,
    /eval\s*\(/g,
    /setTimeout\s*\(\s*['"]/g, // Dynamic code execution
    /localStorage/g,
    /sessionStorage/g,
    /indexedDB/g,
    /connect\s*\(/g,
    /sendMessage\s*\(/g,
  ];

  const SECRET_PATTERNS = [
    /(?:key|token|secret|password|auth|api_key|client_id|client_secret)\s*[:=]\s*['"][\w-]{10,}['"]/gi,
    /AIza[0-9A-Za-z-_]{35}/g, // Google API Key
    /xox[bpgr]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}/g, // Slack Token
    /sk_live_[0-9a-zA-Z]{24}/g, // Stripe Live Key
  ];

  const DEPENDENCY_PATTERNS = [
    /jquery[\w.-]*\.js/i,
    /react[\w.-]*\.js/i,
    /vue[\w.-]*\.js/i,
    /angular[\w.-]*\.js/i,
    /lodash[\w.-]*\.js/i,
    /moment[\w.-]*\.js/i,
    /bootstrap[\w.-]*\.js/i,
  ];

  const files = Object.keys(zip.files);
  for (const fileName of files) {
    if (fileName.endsWith('.js') || fileName.endsWith('.html') || fileName.endsWith('.json')) {
      const content = await zip.files[fileName].async('string');

      // API Calls
      API_PATTERNS.forEach(pattern => {
        const matches = content.match(pattern);
        if (matches) matches.forEach(m => apiCallsSet.add(m.trim()));
      });

      // Secrets
      SECRET_PATTERNS.forEach(pattern => {
        const matches = content.match(pattern);
        if (matches) matches.forEach(m => secretsSet.add('Potential secret found in ' + fileName));
      });

      // Dependencies (from filenames or content)
      DEPENDENCY_PATTERNS.forEach(pattern => {
        if (fileName.match(pattern)) {
          dependenciesSet.add(fileName.split('/').pop() || fileName);
        }
      });

      // Also check manifest.json for specific dependencies if we were parsing it deeper
    }
  }

  return {
    apiCalls: Array.from(apiCallsSet),
    secrets: Array.from(secretsSet),
    dependencies: Array.from(dependenciesSet),
  };
}

function detectVulnerabilities(dependencies: string[]): Vulnerability[] {
  const vulnerabilitiesMap = new Map<string, Vulnerability>();

  dependencies.forEach(dep => {
    if (dep.toLowerCase().includes('jquery')) {
      vulnerabilitiesMap.set('CVE-2020-11022', {
        id: 'CVE-2020-11022',
        severity: 'Medium',
        score: 6.1,
        description: 'Regex in jQuery.htmlPrefilter potentially leads to XSS.',
      });
    }
    if (dep.toLowerCase().includes('lodash')) {
      vulnerabilitiesMap.set('CVE-2020-8203', {
        id: 'CVE-2020-8203',
        severity: 'High',
        score: 7.4,
        description: 'Prototype pollution in lodash via merge and zipObjectDeep.',
      });
    }
  });

  return Array.from(vulnerabilitiesMap.values());
}

function calculateDetailedRisk(permissions: PermissionInfo[], apiCalls: string[], vulnerabilities: Vulnerability[]): { score: number, equation: string } {
  let permissionScore = 0;
  permissions.forEach(p => {
    if (p.risk === 'Critical') permissionScore += 4;
    if (p.risk === 'High') permissionScore += 2;
    if (p.risk === 'Medium') permissionScore += 1;
    if (p.risk === 'Low') permissionScore += 0.2;
  });

  let apiScore = 0;
  if (apiCalls.some(a => a.includes('eval'))) apiScore += 2;
  if (apiCalls.some(a => a.includes('fetch') || a.includes('XMLHttpRequest'))) apiScore += 1;
  if (apiCalls.some(a => a.includes('chrome.cookies'))) apiScore += 1;

  let vulnerabilityScore = 0;
  vulnerabilities.forEach(v => {
    if (v.severity === 'Critical') vulnerabilityScore += 5;
    if (v.severity === 'High') vulnerabilityScore += 3;
    if (v.severity === 'Medium') vulnerabilityScore += 1.5;
    if (v.severity === 'Low') vulnerabilityScore += 0.5;
  });

  const totalRaw = permissionScore + apiScore + vulnerabilityScore;
  const score = Math.min(10.0, Math.round(totalRaw * 10) / 10);

  const equation = `Risk Score = 100 - (PermissionScore(${permissionScore.toFixed(1)}) + APIScore(${apiScore.toFixed(1)}) + VulnerabilityScore(${vulnerabilityScore.toFixed(1)})) * 10`;

  return { score, equation };
}

function calculateReputationScore(reputation: ReputationData): number {
  let score = 0;

  // Rating (0-5 stars) -> max 40 points
  score += (reputation.rating / 5) * 40;

  // User count -> max 40 points
  // Parse user count like "1,000,000+"
  const users = parseInt(reputation.userCount.replace(/[^0-9]/g, '')) || 0;
  if (users > 0) {
    // Logarithmic scale for users, 1M users = 40 points, 100 users = ~13 points
    const userPoints = Math.min(40, (Math.log10(users) / 6) * 40);
    score += userPoints;
  }

  // Recency/Update frequency -> max 20 points
  // Simple heuristic: if updated within last year
  const lastUpdated = new Date(reputation.lastUpdated);
  if (!isNaN(lastUpdated.getTime())) {
    const monthsSinceUpdate = (new Date().getTime() - lastUpdated.getTime()) / (1000 * 60 * 60 * 24 * 30);
    if (monthsSinceUpdate <= 3) score += 20;
    else if (monthsSinceUpdate <= 6) score += 15;
    else if (monthsSinceUpdate <= 12) score += 10;
    else if (monthsSinceUpdate <= 24) score += 5;
  } else {
    // If we can't parse the date (e.g. Edge format), give some baseline if it exists
    if (reputation.lastUpdated) score += 10;
  }

  return Math.min(100, Math.round(score));
}

function getOverallRiskLevel(score: number): 'Low' | 'Medium' | 'High' | 'Critical' {
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  return 'Low';
}
