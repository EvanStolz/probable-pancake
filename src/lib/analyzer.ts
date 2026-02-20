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
}

export interface AnalysisResult {
  name: string;
  version: string;
  permissions: PermissionInfo[];
  apiCalls: string[];
  secrets: string[];
  dependencies: string[];
  vulnerabilities: Vulnerability[];
  cvssScore: number;
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
}

export async function analyzeExtension(file: File | Blob | ArrayBuffer | Uint8Array): Promise<AnalysisResult> {
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

  const permissions = analyzePermissions(manifest.permissions || [], manifest.host_permissions || []);
  const { apiCalls, secrets, dependencies } = await analyzeSourceCode(zip);
  const vulnerabilities = detectVulnerabilities(dependencies);

  const cvssScore = calculateCVSS(permissions, apiCalls, vulnerabilities);
  const riskLevel = getOverallRiskLevel(cvssScore);

  return {
    name: manifest.name || 'Unknown',
    version: manifest.version || '0.0.0',
    permissions,
    apiCalls,
    secrets,
    dependencies,
    vulnerabilities,
    cvssScore,
    riskLevel,
  };
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
        description: 'Regex in jQuery.htmlPrefilter potentially leads to XSS.',
      });
    }
    if (dep.toLowerCase().includes('lodash')) {
      vulnerabilitiesMap.set('CVE-2020-8203', {
        id: 'CVE-2020-8203',
        severity: 'High',
        description: 'Prototype pollution in lodash via merge and zipObjectDeep.',
      });
    }
  });

  return Array.from(vulnerabilitiesMap.values());
}

function calculateCVSS(permissions: PermissionInfo[], apiCalls: string[], vulnerabilities: Vulnerability[]): number {
  let score = 0;

  // Permission based scores
  permissions.forEach(p => {
    if (p.risk === 'Critical') score += 4;
    if (p.risk === 'High') score += 2;
    if (p.risk === 'Medium') score += 1;
    if (p.risk === 'Low') score += 0.2;
  });

  // API Call based scores
  if (apiCalls.some(a => a.includes('eval'))) score += 2;
  if (apiCalls.some(a => a.includes('fetch') || a.includes('XMLHttpRequest'))) score += 1;
  if (apiCalls.some(a => a.includes('chrome.cookies'))) score += 1;

  // Vulnerability based scores
  vulnerabilities.forEach(v => {
    if (v.severity === 'Critical') score += 5;
    if (v.severity === 'High') score += 3;
    if (v.severity === 'Medium') score += 1.5;
    if (v.severity === 'Low') score += 0.5;
  });

  return Math.min(10.0, Math.round(score * 10) / 10);
}

function getOverallRiskLevel(score: number): 'Low' | 'Medium' | 'High' | 'Critical' {
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  return 'Low';
}
