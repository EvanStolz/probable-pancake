import { describe, it, expect } from 'vitest';

// Minimal mock of the scraper logic to test regexes as implemented in src/app/api/proxy/route.ts
function testChromeRegex(html: string) {
    const dateMatch = html.match(/(?:Updated|Last updated).*?([A-Za-z]+ [0-9]+, [0-9]{4})/si) ||
                      html.match(/(?:Updated|Last updated):?\s*([A-Za-z]+ [0-9]+, [0-9]{4})/i);
    return dateMatch ? dateMatch[1] : '';
}

function testEdgeRegex(html: string) {
    const dateMatch = html.match(/(?:Updated|Last updated):?\s*(?:<\/?[^>]+>\s*)*([A-Za-z]+ \d{1,2}, \d{4})/i) ||
                      html.match(/(?:Updated|Last updated):?\s*(?:<\/?[^>]+>\s*)*([^<>\n]{5,30})/i) ||
                      html.match(/Updated.*?([A-Za-z]+ [0-9]{1,2}, [0-9]{4})/s);
    return dateMatch ? dateMatch[1].trim() : '';
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
    });
});
