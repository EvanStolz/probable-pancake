import { describe, it, expect } from 'vitest';

// Minimal mock of the scraper logic to test regexes as implemented in src/app/api/proxy/route.ts
function testChromeRegex(html: string) {
    const dateMatch = html.match(/\b(?:Updated|Last updated)\b.*?([A-Za-z]+ [0-9]+, [0-9]{4})/si) ||
                      html.match(/\b(?:Updated|Last updated)\b:?\s*([A-Za-z]+ [0-9]+, [0-9]{4})/i);
    return dateMatch ? dateMatch[1] : '';
}

function testEdgeRegex(html: string) {
    const dateMatch = html.match(/\b(?:Updated|Last updated)\b:?\s*(?:<\/?[^>]+>\s*)*([A-Za-z]+ \d{1,2}, \d{4})/i) ||
                      html.match(/\b(?:Updated|Last updated)\b:?\s*(?:<\/?[^>]+>\s*)*([^<>\n]{5,30})/i) ||
                      html.match(/\bUpdated\b.*?([A-Za-z]+ [0-9]{1,2}, [0-9]{4})/s);
    return dateMatch ? dateMatch[1].trim() : '';
}

function testEdgePublisherFallback(html: string) {
    const titleMatch = html.match(/<title>(.*?) - Microsoft Edge Addons<\/title>/i);
    if (titleMatch) {
        const titleContent = titleMatch[1];
        return titleContent.includes(':') ? titleContent.split(':')[0].trim() : titleContent.trim();
    }
    return '';
}

describe('Scraper Regex Tests', () => {
    describe('Chrome Scraper', () => {
        it('should match Chrome date with dotall', () => {
            const html = '<div>Updated</div><div>November 18, 2024</div>';
            expect(testChromeRegex(html)).toBe('November 18, 2024');
        });

        it('should match Chrome date with newline', () => {
            const html = 'Updated\nNovember 18, 2024';
            expect(testChromeRegex(html)).toBe('November 18, 2024');
        });

        it('should handle "Last updated" for Chrome', () => {
            const html = 'Last updated: November 18, 2024';
            expect(testChromeRegex(html)).toBe('November 18, 2024');
        });
    });

    describe('Edge Scraper', () => {
        it('should match Edge date with tags', () => {
            const html = '<span>Updated</span> <span>November 18, 2024</span>';
            expect(testEdgeRegex(html)).toBe('November 18, 2024');
        });

        it('should handle "Last updated" for Edge', () => {
            const html = 'Last updated: November 18, 2024';
            expect(testEdgeRegex(html)).toBe('November 18, 2024');
        });

        it('should NOT match UpdatedLinks in Edge footer', () => {
            const html = '<footer data-footer-footprint="/Edgestoreweb/EdgestorewebFooterUpdatedLinks, fromService: True"></footer>';
            expect(testEdgeRegex(html)).not.toBe('Links, fromService: True');
        });

        it('should match Edge date even with nested spans', () => {
            const html = '<div class="lastUpdated"><span class="label">Updated:</span> <span class="date">October 24, 2024</span></div>';
            expect(testEdgeRegex(html)).toBe('October 24, 2024');
        });

        it('should handle Edge date with extra whitespace', () => {
            const html = 'Updated:    November   18,   2024';
            expect(testEdgeRegex(html)).toBe('November   18,   2024');
        });

        it('should extract publisher from Edge title tag', () => {
            const html = '<title>Dark Reader - Microsoft Edge Addons</title>';
            expect(testEdgePublisherFallback(html)).toBe('Dark Reader');
        });

        it('should extract publisher from Edge title tag with colon', () => {
            const html = '<title>uBlock Origin: An efficient blocker - Microsoft Edge Addons</title>';
            expect(testEdgePublisherFallback(html)).toBe('uBlock Origin');
        });
    });
});
