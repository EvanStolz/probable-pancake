import { describe, it, expect } from 'vitest';
import { calculateReputationScore, calculateDetailedRisk, calculateEntropy } from '../analyzer';

describe('Scoring Logic', () => {
  describe('Reputation Score', () => {
    it('should calculate perfect score for ideal extension', () => {
      const reputation = {
        publisher: 'Trusted Dev',
        rating: 5,
        ratingCount: 100000,
        userCount: '10,000,000+',
        lastUpdated: new Date().toISOString(),
        isFeatured: true,
        isVerifiedPublisher: true,
      };
      const score = calculateReputationScore(reputation);
      expect(score).toBe(100);
    });

    it('should calculate zero score for new unknown extension', () => {
      const reputation = {
        publisher: 'Newbie',
        rating: 0,
        ratingCount: 0,
        userCount: '0',
        lastUpdated: '2020-01-01',
        isFeatured: false,
        isVerifiedPublisher: false,
      };
      const score = calculateReputationScore(reputation);
      expect(score).toBe(0);
    });

    it('should handle log scaling correctly for ratings and users', () => {
        const rep1 = {
          publisher: 'Dev',
          rating: 4,
          ratingCount: 100, // log10(100) = 2. (2/5)*15 = 6
          userCount: '1,000', // log10(1000) = 3. (3/7)*20 = 8.57
          lastUpdated: new Date().toISOString(), // 15 pts
          isFeatured: false,
          isVerifiedPublisher: false,
        };
        // 0 (pub) + 16 (rating) + 6 (ratingCount) + 8.57 (users) + 15 (updated) + 0 (featured) = 45.57 -> 46
        expect(calculateReputationScore(rep1)).toBe(46);
    });
  });

  describe('Risk Score', () => {
    it('should calculate zero risk for clean MV3 extension', () => {
      const score = calculateDetailedRisk([], [], 3, 0);
      expect(score.score).toBe(0);
      expect(score.level).toBe('Low');
    });

    it('should calculate high risk for vulnerable MV2 extension with obfuscation', () => {
      const permissions = [
        { permission: '<all_urls>', risk: 'Critical', description: '' } as any
      ];
      const vulnerabilities = [
        { id: 'CVE-1', severity: 'Critical', score: 9.8, description: '' }
      ];
      // Permissions: 10
      // CVE Count: 4
      // CVSS: log10(10.8)/log10(11) * 25 = 1.033 / 1.041 * 25 = 24.8 -> ~25
      // MV2: 5
      // Obf: 10
      // Total: 10 + 4 + 25 + 5 + 10 = 54
      const score = calculateDetailedRisk(permissions, vulnerabilities, 2, 10);
      expect(score.score).toBe(54);
      expect(score.level).toBe('High');
    });

    it('should cap permission score at 40', () => {
        const permissions = Array(10).fill({ permission: 'p', risk: 'Critical', description: '' });
        const score = calculateDetailedRisk(permissions, [], 3, 0);
        expect(score.score).toBe(40);
    });
  });

  describe('Entropy calculation', () => {
    it('should calculate low entropy for repetitive strings', () => {
      const h = calculateEntropy('aaaaaaaaaaaaaaaa');
      expect(h).toBe(0);
    });

    it('should calculate higher entropy for random strings', () => {
      const h = calculateEntropy('abcdefghijklmnopqrstuvwxyz0123456789');
      expect(h).toBeGreaterThan(5);
    });
  });
});
