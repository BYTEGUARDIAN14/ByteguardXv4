import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  RefreshControl,
  TouchableOpacity,
  Alert,
  Dimensions
} from 'react-native';
import { Card, Button, ProgressBar, Chip } from 'react-native-paper';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { LineChart, PieChart } from 'react-native-chart-kit';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import { SecurityService } from '../services/SecurityService';
import { NotificationService } from '../services/NotificationService';

const { width: screenWidth } = Dimensions.get('window');

interface SecurityMetrics {
  totalScans: number;
  criticalIssues: number;
  highIssues: number;
  mediumIssues: number;
  lowIssues: number;
  lastScanDate: string;
  securityScore: number;
  trendData: number[];
}

interface RecentScan {
  id: string;
  name: string;
  date: string;
  issues: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'completed' | 'running' | 'failed';
}

const HomeScreen: React.FC = () => {
  const { user } = useAuth();
  const { theme } = useTheme();
  const [metrics, setMetrics] = useState<SecurityMetrics | null>(null);
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      
      // Load security metrics
      const metricsData = await SecurityService.getSecurityMetrics();
      setMetrics(metricsData);
      
      // Load recent scans
      const scansData = await SecurityService.getRecentScans(5);
      setRecentScans(scansData);
      
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
      Alert.alert('Error', 'Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await loadDashboardData();
    setRefreshing(false);
  };

  const handleQuickScan = () => {
    // Navigate to scan screen with quick scan preset
    // navigation.navigate('Scan', { scanType: 'quick' });
  };

  const handleViewAllScans = () => {
    // navigation.navigate('Reports');
  };

  const getSecurityScoreColor = (score: number) => {
    if (score >= 80) return '#4CAF50'; // Green
    if (score >= 60) return '#FF9800'; // Orange
    return '#F44336'; // Red
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return '#F44336';
      case 'high': return '#FF5722';
      case 'medium': return '#FF9800';
      case 'low': return '#4CAF50';
      default: return '#9E9E9E';
    }
  };

  const renderSecurityOverview = () => {
    if (!metrics) return null;

    const pieData = [
      {
        name: 'Critical',
        population: metrics.criticalIssues,
        color: '#F44336',
        legendFontColor: theme.colors.text,
        legendFontSize: 12,
      },
      {
        name: 'High',
        population: metrics.highIssues,
        color: '#FF5722',
        legendFontColor: theme.colors.text,
        legendFontSize: 12,
      },
      {
        name: 'Medium',
        population: metrics.mediumIssues,
        color: '#FF9800',
        legendFontColor: theme.colors.text,
        legendFontSize: 12,
      },
      {
        name: 'Low',
        population: metrics.lowIssues,
        color: '#4CAF50',
        legendFontColor: theme.colors.text,
        legendFontSize: 12,
      },
    ].filter(item => item.population > 0);

    return (
      <Card style={styles.card}>
        <Card.Content>
          <Text style={[styles.cardTitle, { color: theme.colors.text }]}>
            Security Overview
          </Text>
          
          <View style={styles.scoreContainer}>
            <View style={styles.scoreCircle}>
              <Text style={[styles.scoreText, { color: getSecurityScoreColor(metrics.securityScore) }]}>
                {metrics.securityScore}
              </Text>
              <Text style={[styles.scoreLabel, { color: theme.colors.text }]}>
                Security Score
              </Text>
            </View>
          </View>

          {pieData.length > 0 && (
            <PieChart
              data={pieData}
              width={screenWidth - 80}
              height={200}
              chartConfig={{
                backgroundColor: theme.colors.surface,
                backgroundGradientFrom: theme.colors.surface,
                backgroundGradientTo: theme.colors.surface,
                color: (opacity = 1) => `rgba(255, 255, 255, ${opacity})`,
              }}
              accessor="population"
              backgroundColor="transparent"
              paddingLeft="15"
              absolute
            />
          )}
        </Card.Content>
      </Card>
    );
  };

  const renderQuickActions = () => (
    <Card style={styles.card}>
      <Card.Content>
        <Text style={[styles.cardTitle, { color: theme.colors.text }]}>
          Quick Actions
        </Text>
        
        <View style={styles.actionButtons}>
          <TouchableOpacity
            style={[styles.actionButton, { backgroundColor: theme.colors.primary }]}
            onPress={handleQuickScan}
          >
            <Icon name="shield-search" size={24} color="white" />
            <Text style={styles.actionButtonText}>Quick Scan</Text>
          </TouchableOpacity>
          
          <TouchableOpacity
            style={[styles.actionButton, { backgroundColor: theme.colors.secondary }]}
            onPress={() => {/* Navigate to deep scan */}}
          >
            <Icon name="shield-check" size={24} color="white" />
            <Text style={styles.actionButtonText}>Deep Scan</Text>
          </TouchableOpacity>
        </View>
        
        <View style={styles.actionButtons}>
          <TouchableOpacity
            style={[styles.actionButton, { backgroundColor: '#4CAF50' }]}
            onPress={() => {/* Navigate to reports */}}
          >
            <Icon name="file-document" size={24} color="white" />
            <Text style={styles.actionButtonText}>View Reports</Text>
          </TouchableOpacity>
          
          <TouchableOpacity
            style={[styles.actionButton, { backgroundColor: '#FF9800' }]}
            onPress={() => {/* Navigate to settings */}}
          >
            <Icon name="cog" size={24} color="white" />
            <Text style={styles.actionButtonText}>Settings</Text>
          </TouchableOpacity>
        </View>
      </Card.Content>
    </Card>
  );

  const renderRecentScans = () => (
    <Card style={styles.card}>
      <Card.Content>
        <View style={styles.cardHeader}>
          <Text style={[styles.cardTitle, { color: theme.colors.text }]}>
            Recent Scans
          </Text>
          <TouchableOpacity onPress={handleViewAllScans}>
            <Text style={[styles.viewAllText, { color: theme.colors.primary }]}>
              View All
            </Text>
          </TouchableOpacity>
        </View>
        
        {recentScans.map((scan) => (
          <View key={scan.id} style={styles.scanItem}>
            <View style={styles.scanInfo}>
              <Text style={[styles.scanName, { color: theme.colors.text }]}>
                {scan.name}
              </Text>
              <Text style={[styles.scanDate, { color: theme.colors.text + '80' }]}>
                {scan.date}
              </Text>
            </View>
            
            <View style={styles.scanStatus}>
              <Chip
                mode="outlined"
                style={{
                  backgroundColor: getSeverityColor(scan.severity) + '20',
                  borderColor: getSeverityColor(scan.severity)
                }}
                textStyle={{ color: getSeverityColor(scan.severity) }}
              >
                {scan.issues} issues
              </Chip>
              
              <Icon
                name={
                  scan.status === 'completed' ? 'check-circle' :
                  scan.status === 'running' ? 'clock' : 'alert-circle'
                }
                size={20}
                color={
                  scan.status === 'completed' ? '#4CAF50' :
                  scan.status === 'running' ? '#FF9800' : '#F44336'
                }
                style={styles.statusIcon}
              />
            </View>
          </View>
        ))}
        
        {recentScans.length === 0 && (
          <View style={styles.emptyState}>
            <Icon name="shield-search" size={48} color={theme.colors.text + '40'} />
            <Text style={[styles.emptyStateText, { color: theme.colors.text + '60' }]}>
              No scans yet. Start your first security scan!
            </Text>
          </View>
        )}
      </Card.Content>
    </Card>
  );

  if (loading) {
    return (
      <View style={[styles.container, styles.centered, { backgroundColor: theme.colors.background }]}>
        <ProgressBar indeterminate color={theme.colors.primary} />
        <Text style={[styles.loadingText, { color: theme.colors.text }]}>
          Loading dashboard...
        </Text>
      </View>
    );
  }

  return (
    <ScrollView
      style={[styles.container, { backgroundColor: theme.colors.background }]}
      refreshControl={
        <RefreshControl refreshing={refreshing} onRefresh={onRefresh} />
      }
    >
      <View style={styles.header}>
        <Text style={[styles.welcomeText, { color: theme.colors.text }]}>
          Welcome back, {user?.name || 'User'}!
        </Text>
        <Text style={[styles.subtitleText, { color: theme.colors.text + '80' }]}>
          Here's your security overview
        </Text>
      </View>

      {renderSecurityOverview()}
      {renderQuickActions()}
      {renderRecentScans()}
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 16,
  },
  centered: {
    justifyContent: 'center',
    alignItems: 'center',
  },
  header: {
    marginBottom: 20,
  },
  welcomeText: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 4,
  },
  subtitleText: {
    fontSize: 16,
  },
  card: {
    marginBottom: 16,
    elevation: 4,
  },
  cardTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 16,
  },
  cardHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 16,
  },
  viewAllText: {
    fontSize: 14,
    fontWeight: '600',
  },
  scoreContainer: {
    alignItems: 'center',
    marginBottom: 20,
  },
  scoreCircle: {
    alignItems: 'center',
  },
  scoreText: {
    fontSize: 48,
    fontWeight: 'bold',
  },
  scoreLabel: {
    fontSize: 14,
    marginTop: 4,
  },
  actionButtons: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 12,
  },
  actionButton: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 12,
    borderRadius: 8,
    marginHorizontal: 4,
  },
  actionButtonText: {
    color: 'white',
    fontWeight: '600',
    marginLeft: 8,
  },
  scanItem: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderBottomColor: '#E0E0E0',
  },
  scanInfo: {
    flex: 1,
  },
  scanName: {
    fontSize: 16,
    fontWeight: '600',
    marginBottom: 2,
  },
  scanDate: {
    fontSize: 14,
  },
  scanStatus: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  statusIcon: {
    marginLeft: 8,
  },
  emptyState: {
    alignItems: 'center',
    paddingVertical: 32,
  },
  emptyStateText: {
    fontSize: 16,
    textAlign: 'center',
    marginTop: 12,
  },
  loadingText: {
    marginTop: 16,
    fontSize: 16,
  },
});

export default HomeScreen;
