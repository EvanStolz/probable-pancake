import { describe, it, expect } from 'vitest';
import { extractExtensionId } from '../utils';

describe('extractExtensionId', () => {
  it('should extract Chrome extension ID from new URL format', () => {
    const url = 'https://chromewebstore.google.com/detail/google-translate/aapbdbdomjkkjkaonfhkkikfgjllcleb';
    const result = extractExtensionId(url);
    expect(result).toEqual({ id: 'aapbdbdomjkkjkaonfhkkikfgjllcleb', store: 'chrome' });
  });

  it('should extract Chrome extension ID from old URL format', () => {
    const url = 'https://chrome.google.com/webstore/detail/google-translate/aapbdbdomjkkjkaonfhkkikfgjllcleb';
    const result = extractExtensionId(url);
    expect(result).toEqual({ id: 'aapbdbdomjkkjkaonfhkkikfgjllcleb', store: 'chrome' });
  });

  it('should extract Edge extension ID', () => {
    const url = 'https://microsoftedge.microsoft.com/addons/detail/ublock-origin/odlbpnoocpeebfbbnocajebccdbogpbe';
    const result = extractExtensionId(url);
    expect(result).toEqual({ id: 'odlbpnoocpeebfbbnocajebccdbogpbe', store: 'edge' });
  });

  it('should return null for invalid URLs', () => {
    expect(extractExtensionId('https://google.com')).toBeNull();
    expect(extractExtensionId('https://chromewebstore.google.com/detail/google-translate/too-short')).toBeNull();
  });
});
