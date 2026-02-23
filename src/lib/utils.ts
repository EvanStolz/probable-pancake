export function extractExtensionId(url: string): { id: string; store: 'chrome' | 'edge'; isRawId: boolean } | null {
  const trimmed = url.trim();

  // If it's a 32-character ID, default to Edge as requested
  if (/^[a-z0-9]{32}$/i.test(trimmed)) {
    return { id: trimmed.toLowerCase(), store: 'edge', isRawId: true };
  }

  if (url.includes('chrome.google.com/webstore') || url.includes('chromewebstore.google.com')) {
    const match = url.match(/\/([a-p]{32})/i);
    if (match) {
      return { id: match[1].toLowerCase(), store: 'chrome', isRawId: false };
    }
  } else if (url.includes('microsoftedge.microsoft.com/addons')) {
    const match = url.match(/\/([a-z0-9]{32})/i);
    if (match) {
      return { id: match[1].toLowerCase(), store: 'edge', isRawId: false };
    }
    // Fallback for Edge URLs that might not match the regex but have the ID at the end
    const parts = url.split('/');
    const lastPart = parts[parts.length - 1].split('?')[0];
    if (lastPart.length === 32) {
      return { id: lastPart.toLowerCase(), store: 'edge', isRawId: false };
    }
  }
  return null;
}
