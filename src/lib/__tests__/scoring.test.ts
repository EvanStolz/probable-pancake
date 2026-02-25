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
      const result = calculateReputationScore(reputation);
      expect(result.score).toBe(100);
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
      const result = calculateReputationScore(reputation);
      expect(result.score).toBe(0);
    });

    it('should handle log scaling correctly for ratings and users', () => {
        const rep1 = {
          publisher: 'Dev',
          rating: 4,
          ratingCount: 100, // log10(100) = 2. (2/5)*20 = 8
          userCount: '1,000', // log10(1000) = 3. (3/7)*30 = 12.857...
          lastUpdated: new Date().toISOString(), // 30 pts
          isFeatured: false,
          isVerifiedPublisher: false,
        };
        // 16 (rating) + 8 (ratingCount) + 12.86 (users) + 30 (updated) = 66.86 -> 67
        expect(calculateReputationScore(rep1).score).toBe(67);
    });

    it('should penalize suspiciously low rating count for high user count', () => {
      const rep = {
        publisher: 'Suspicious',
        rating: 5,
        ratingCount: 50, // log10(50) = 1.698 -> (1.698/5)*20 = 6.79
        userCount: '1,000,000', // log10(1M) = 6 -> (6/7)*30 = 25.71
        lastUpdated: new Date().toISOString(), // 30 pts
        isFeatured: false,
        isVerifiedPublisher: false,
      };
      // Ratio = 50 / 1M = 0.00005 (< 0.0001)
      // ratingCount = 6.79 * 0.5 = 3.4
      // Total = 20 + 3.4 + 25.71 + 30 = 79.11 -> 79
      expect(calculateReputationScore(rep).score).toBe(79);
    });

    it('should penalize suspiciously high rating count for user count', () => {
      const rep = {
        publisher: 'Bot Farm?',
        rating: 5,
        ratingCount: 200, // log10(200) = 2.30 -> (2.3/5)*20 = 9.2
        userCount: '1,000', // log10(1000) = 3 -> (3/7)*30 = 12.86
        lastUpdated: new Date().toISOString(), // 30 pts
        isFeatured: false,
        isVerifiedPublisher: false,
      };
      // Ratio = 200 / 1000 = 0.2 (> 0.1)
      // ratingCount = 9.2 * 0.5 = 4.6
      // Total = 20 + 4.6 + 12.86 + 30 = 67.46 -> 67
      expect(calculateReputationScore(rep).score).toBe(67);
    });

    it('should not penalize high ratio for low user counts', () => {
      const rep = {
        publisher: 'Small Dev',
        rating: 5,
        ratingCount: 10, // log10(10) = 1 -> (1/5)*20 = 4
        userCount: '50', // log10(50) = 1.7 -> (1.7/7)*30 = 7.28
        lastUpdated: new Date().toISOString(), // 30 pts
        isFeatured: false,
        isVerifiedPublisher: false,
      };
      // Ratio = 10 / 50 = 0.2 (> 0.1), but users < 100
      // ratingCount = 4 (no penalty)
      // Total = 20 + 4 + 7.28 + 30 = 61.28 -> 61
      expect(calculateReputationScore(rep).score).toBe(61);
    });

    it('should handle zero ratings correctly', () => {
      const rep = {
        publisher: 'No Ratings',
        rating: 5, // Should be ignored because ratingCount is 0
        ratingCount: 0,
        userCount: '10,000', // log10(10k) = 4 -> (4/7)*30 = 17.14
        lastUpdated: new Date().toISOString(), // 30 pts
        isFeatured: false,
        isVerifiedPublisher: false,
      };
      // rating = 0, ratingCount = 0
      // Total = 0 + 0 + 17.14 + 30 = 47.14 -> 47
      expect(calculateReputationScore(rep).score).toBe(47);
    });

    it('should give 0 points for updates older than 18 months', () => {
      const longAgo = new Date();
      longAgo.setMonth(longAgo.getMonth() - 19);
      const rep = {
        publisher: 'Old Dev',
        rating: 5,
        ratingCount: 1000,
        userCount: '10,000',
        lastUpdated: longAgo.toISOString(),
        isFeatured: false,
        isVerifiedPublisher: false,
      };
      const result = calculateReputationScore(rep);
      expect(result.breakdown.updated).toBe(0);
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
      // CVSS: (9.8/10)^1.5 * 25 = 0.98^1.5 * 25 = 24.25
      // MV2: 5
      // Obf: 10
      // Total: 10 + 4 + 24.25 + 5 + 10 = 53.25 -> 53
      const score = calculateDetailedRisk(permissions, vulnerabilities, 2, 10);
      expect(score.score).toBe(53);
      expect(score.level).toBe('High');
    });

    it('should cap permission score at 40', () => {
        const permissions = Array(10).fill({ permission: 'p', risk: 'Critical', description: '' });
        const score = calculateDetailedRisk(permissions, [], 3, 0);
        expect(score.score).toBe(40);
    });

    it('should deduplicate CVEs in risk calculation', () => {
      const permissions = [];
      const vulnerabilities = [
        { id: 'CVE-1', severity: 'Medium', score: 5, description: '' } as any,
        { id: 'CVE-1', severity: 'Medium', score: 5, description: '' } as any
      ];
      // Should be 1 CVE * 4 = 4 points, not 8.
      const result = calculateDetailedRisk(permissions, vulnerabilities, 3, 0);
      expect(result.equation).toContain('CVEs(4)');
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
