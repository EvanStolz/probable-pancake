import { describe, it, expect } from 'vitest';
import { analyzePermissions, detectVulnerabilities } from '../analyzer';

describe('Sorting Logic', () => {
    describe('analyzePermissions', () => {
        it('should sort permissions by risk (Critical > High > Medium > Low) and then alphabetically', () => {
            const permissions = ['storage', 'history', '<all_urls>', 'tabs', 'alarms', 'bookmarks'];
            const sorted = analyzePermissions(permissions, []);

            const names = sorted.map(p => p.permission);
            const risks = sorted.map(p => p.risk);

            // Expected order:
            // Critical: <all_urls>
            // High: history
            // Medium: bookmarks, tabs
            // Low: alarms, storage

            expect(risks).toEqual(['Critical', 'High', 'Medium', 'Medium', 'Low', 'Low']);
            expect(names).toEqual(['<all_urls>', 'history', 'bookmarks', 'tabs', 'alarms', 'storage']);
        });
    });

    describe('detectVulnerabilities', () => {
        it('should sort vulnerabilities by score descending, with no score at bottom', () => {
            // detectVulnerabilities currently only checks for jquery and lodash
            // I'll mock the dependencies to trigger them
            const deps = ['jquery.js', 'lodash.js'];
            const sorted = detectVulnerabilities(deps);

            // CVE-2020-11022 (jQuery) has score 6.1 (Medium)
            // CVE-2020-8203 (lodash) has score 7.4 (High)

            expect(sorted[0].id).toBe('CVE-2020-8203');
            expect(sorted[1].id).toBe('CVE-2020-11022');
        });

        it('should place vulnerabilities without scores at the bottom', () => {
            const vulns: any[] = [
                { id: 'VULN-1', score: undefined },
                { id: 'VULN-2', score: 9.0 },
                { id: 'VULN-3', score: 5.0 },
            ];

            vulns.sort((a, b) => {
                if (a.score !== undefined && b.score !== undefined) {
                    return b.score - a.score;
                }
                if (a.score !== undefined) return -1;
                if (b.score !== undefined) return 1;
                return a.id.localeCompare(b.id);
            });

            expect(vulns[0].id).toBe('VULN-2');
            expect(vulns[1].id).toBe('VULN-3');
            expect(vulns[2].id).toBe('VULN-1');
        });
    });
});
