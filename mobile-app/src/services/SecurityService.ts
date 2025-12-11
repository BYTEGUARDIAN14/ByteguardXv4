import axios, { AxiosInstance, AxiosResponse } from 'axios';
import * as SecureStore from 'expo-secure-store';
import { Alert } from 'react-native';

export interface ScanConfig {
  scanSecrets: boolean;
  scanVulnerabilities: boolean;
  scanDependencies: boolean;
  includeTests: boolean;
  maxFileSizeMb: number;
  scanTimeout: number;
}

export interface SecurityMetrics {
  totalScans: number;
  criticalIssues: number;
  highIssues: number;
  mediumIssues: number;
  lowIssues: number;
  lastScanDate: string;
  securityScore: number;
  trendData: number[];
}

export interface ScanResult {
  id: string;
  status: 'running' | 'completed' | 'failed';
  progress: number;
  findings: SecurityFinding[];
  metadata: {
    startTime: string;
    endTime?: string;
    filesScanned: number;
    totalFiles: number;
    scanType: string;
  };
}

export interface SecurityFinding {
  id: string;
  type: 'secret' | 'vulnerability' | 'dependency';
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  file: string;
  line: number;
  column?: number;
  code?: string;
  recommendation: string;
  cwe?: string;
  cvss?: number;
}

export interface RecentScan {
  id: string;
  name: string;
  date: string;
  issues: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'completed' | 'running' | 'failed';
}

class SecurityServiceClass {
  private api: AxiosInstance;
  private baseURL: string;

  constructor() {
    this.baseURL = process.env.EXPO_PUBLIC_API_URL || 'https://api.byteguardx.com';
    
    this.api = axios.create({
      baseURL: this.baseURL,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'ByteGuardX-Mobile/1.0.0',
      },
    });

    // Request interceptor to add auth token
    this.api.interceptors.request.use(
      async (config) => {
        const token = await SecureStore.getItemAsync('auth_token');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    // Response interceptor for error handling
    this.api.interceptors.response.use(
      (response) => response,
      async (error) => {
        if (error.response?.status === 401) {
          // Token expired, redirect to login
          await SecureStore.deleteItemAsync('auth_token');
          // Navigate to login screen
        }
        return Promise.reject(error);
      }
    );
  }

  async getSecurityMetrics(): Promise<SecurityMetrics> {
    try {
      const response: AxiosResponse<SecurityMetrics> = await this.api.get('/api/metrics/security');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch security metrics:', error);
      throw new Error('Failed to fetch security metrics');
    }
  }

  async getRecentScans(limit: number = 5): Promise<RecentScan[]> {
    try {
      const response: AxiosResponse<{ scans: RecentScan[] }> = await this.api.get(
        `/api/scans/recent?limit=${limit}`
      );
      return response.data.scans;
    } catch (error) {
      console.error('Failed to fetch recent scans:', error);
      throw new Error('Failed to fetch recent scans');
    }
  }

  async startScan(config: ScanConfig, files?: string[]): Promise<string> {
    try {
      const scanData = {
        config,
        files: files || [],
        scan_type: files ? 'files' : 'quick',
      };

      const response: AxiosResponse<{ scan_id: string }> = await this.api.post(
        '/api/scans/start',
        scanData
      );
      
      return response.data.scan_id;
    } catch (error) {
      console.error('Failed to start scan:', error);
      throw new Error('Failed to start scan');
    }
  }

  async getScanStatus(scanId: string): Promise<ScanResult> {
    try {
      const response: AxiosResponse<ScanResult> = await this.api.get(`/api/scans/${scanId}`);
      return response.data;
    } catch (error) {
      console.error('Failed to get scan status:', error);
      throw new Error('Failed to get scan status');
    }
  }

  async cancelScan(scanId: string): Promise<void> {
    try {
      await this.api.post(`/api/scans/${scanId}/cancel`);
    } catch (error) {
      console.error('Failed to cancel scan:', error);
      throw new Error('Failed to cancel scan');
    }
  }

  async getAllReports(): Promise<any[]> {
    try {
      const response: AxiosResponse<{ reports: any[] }> = await this.api.get('/api/reports');
      return response.data.reports;
    } catch (error) {
      console.error('Failed to fetch reports:', error);
      throw new Error('Failed to fetch reports');
    }
  }

  async getReport(reportId: string): Promise<any> {
    try {
      const response: AxiosResponse<any> = await this.api.get(`/api/reports/${reportId}`);
      return response.data;
    } catch (error) {
      console.error('Failed to fetch report:', error);
      throw new Error('Failed to fetch report');
    }
  }

  async deleteReport(reportId: string): Promise<void> {
    try {
      await this.api.delete(`/api/reports/${reportId}`);
    } catch (error) {
      console.error('Failed to delete report:', error);
      throw new Error('Failed to delete report');
    }
  }

  async exportReport(reportId: string, format: 'pdf' | 'json' | 'csv' = 'pdf'): Promise<Blob> {
    try {
      const response: AxiosResponse<Blob> = await this.api.get(
        `/api/reports/${reportId}/export?format=${format}`,
        { responseType: 'blob' }
      );
      return response.data;
    } catch (error) {
      console.error('Failed to export report:', error);
      throw new Error('Failed to export report');
    }
  }

  async getUserSettings(): Promise<any> {
    try {
      const response: AxiosResponse<any> = await this.api.get('/api/user/settings');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch user settings:', error);
      return null;
    }
  }

  async updateUserSettings(settings: any): Promise<void> {
    try {
      await this.api.put('/api/user/settings', settings);
    } catch (error) {
      console.error('Failed to update user settings:', error);
      throw new Error('Failed to update user settings');
    }
  }

  async exportUserData(): Promise<void> {
    try {
      await this.api.post('/api/user/export-data');
    } catch (error) {
      console.error('Failed to export user data:', error);
      throw new Error('Failed to export user data');
    }
  }

  async deleteAccount(): Promise<void> {
    try {
      await this.api.delete('/api/user/account');
    } catch (error) {
      console.error('Failed to delete account:', error);
      throw new Error('Failed to delete account');
    }
  }

  async uploadFile(file: any): Promise<string> {
    try {
      const formData = new FormData();
      formData.append('file', {
        uri: file.uri,
        type: file.type || 'application/octet-stream',
        name: file.name || 'file',
      } as any);

      const response: AxiosResponse<{ file_id: string }> = await this.api.post(
        '/api/files/upload',
        formData,
        {
          headers: {
            'Content-Type': 'multipart/form-data',
          },
        }
      );

      return response.data.file_id;
    } catch (error) {
      console.error('Failed to upload file:', error);
      throw new Error('Failed to upload file');
    }
  }

  async getVulnerabilityDetails(findingId: string): Promise<any> {
    try {
      const response: AxiosResponse<any> = await this.api.get(`/api/vulnerabilities/${findingId}`);
      return response.data;
    } catch (error) {
      console.error('Failed to fetch vulnerability details:', error);
      throw new Error('Failed to fetch vulnerability details');
    }
  }

  async getFixSuggestion(findingId: string): Promise<string> {
    try {
      const response: AxiosResponse<{ suggestion: string }> = await this.api.get(
        `/api/vulnerabilities/${findingId}/fix`
      );
      return response.data.suggestion;
    } catch (error) {
      console.error('Failed to fetch fix suggestion:', error);
      throw new Error('Failed to fetch fix suggestion');
    }
  }

  async markFindingAsResolved(findingId: string): Promise<void> {
    try {
      await this.api.post(`/api/vulnerabilities/${findingId}/resolve`);
    } catch (error) {
      console.error('Failed to mark finding as resolved:', error);
      throw new Error('Failed to mark finding as resolved');
    }
  }

  async markFindingAsFalsePositive(findingId: string, reason?: string): Promise<void> {
    try {
      await this.api.post(`/api/vulnerabilities/${findingId}/false-positive`, {
        reason: reason || 'User marked as false positive',
      });
    } catch (error) {
      console.error('Failed to mark finding as false positive:', error);
      throw new Error('Failed to mark finding as false positive');
    }
  }

  async getHealthStatus(): Promise<any> {
    try {
      const response: AxiosResponse<any> = await this.api.get('/health');
      return response.data;
    } catch (error) {
      console.error('Failed to check health status:', error);
      throw new Error('Failed to check health status');
    }
  }

  // Offline support methods
  async syncOfflineData(): Promise<void> {
    try {
      // Implementation for syncing offline data when connection is restored
      const offlineData = await this.getOfflineData();
      if (offlineData.length > 0) {
        await this.api.post('/api/sync/offline-data', { data: offlineData });
        await this.clearOfflineData();
      }
    } catch (error) {
      console.error('Failed to sync offline data:', error);
    }
  }

  private async getOfflineData(): Promise<any[]> {
    try {
      const data = await SecureStore.getItemAsync('offline_data');
      return data ? JSON.parse(data) : [];
    } catch (error) {
      return [];
    }
  }

  private async clearOfflineData(): Promise<void> {
    try {
      await SecureStore.deleteItemAsync('offline_data');
    } catch (error) {
      console.error('Failed to clear offline data:', error);
    }
  }
}

export const SecurityService = new SecurityServiceClass();
