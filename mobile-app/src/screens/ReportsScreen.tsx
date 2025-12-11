import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  RefreshControl,
  TouchableOpacity,
  Alert,
  FlatList
} from 'react-native';
import { Card, Button, Chip, Searchbar, FAB } from 'react-native-paper';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { useNavigation } from '@react-navigation/native';
import { useTheme } from '../context/ThemeContext';
import { SecurityService } from '../services/SecurityService';

interface ScanReport {
  id: string;
  name: string;
  date: string;
  status: 'completed' | 'running' | 'failed';
  totalIssues: number;
  criticalIssues: number;
  highIssues: number;
  mediumIssues: number;
  lowIssues: number;
  scanType: 'quick' | 'deep' | 'custom';
  duration: number;
  filesScanned: number;
}

const ReportsScreen: React.FC = () => {
  const navigation = useNavigation();
  const { theme } = useTheme();
  const [reports, setReports] = useState<ScanReport[]>([]);
  const [filteredReports, setFilteredReports] = useState<ScanReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterStatus, setFilterStatus] = useState<string>('all');

  useEffect(() => {
    loadReports();
  }, []);

  useEffect(() => {
    filterReports();
  }, [reports, searchQuery, filterStatus]);

  const loadReports = async () => {
    try {
      setLoading(true);
      const reportsData = await SecurityService.getAllReports();
      setReports(reportsData);
    } catch (error) {
      console.error('Failed to load reports:', error);
      Alert.alert('Error', 'Failed to load reports');
    } finally {
      setLoading(false);
    }
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await loadReports();
    setRefreshing(false);
  };

  const filterReports = () => {
    let filtered = reports;

    // Filter by search query
    if (searchQuery) {
      filtered = filtered.filter(report =>
        report.name.toLowerCase().includes(searchQuery.toLowerCase())
      );
    }

    // Filter by status
    if (filterStatus !== 'all') {
      filtered = filtered.filter(report => report.status === filterStatus);
    }

    setFilteredReports(filtered);
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

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return '#4CAF50';
      case 'running': return '#FF9800';
      case 'failed': return '#F44336';
      default: return '#9E9E9E';
    }
  };

  const handleReportPress = (report: ScanReport) => {
    navigation.navigate('ReportDetail', { reportId: report.id });
  };

  const handleDeleteReport = async (reportId: string) => {
    Alert.alert(
      'Delete Report',
      'Are you sure you want to delete this report?',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Delete',
          style: 'destructive',
          onPress: async () => {
            try {
              await SecurityService.deleteReport(reportId);
              await loadReports();
            } catch (error) {
              Alert.alert('Error', 'Failed to delete report');
            }
          }
        }
      ]
    );
  };

  const renderReportCard = ({ item: report }: { item: ScanReport }) => (
    <Card style={styles.reportCard} onPress={() => handleReportPress(report)}>
      <Card.Content>
        <View style={styles.reportHeader}>
          <View style={styles.reportInfo}>
            <Text style={[styles.reportName, { color: theme.colors.text }]}>
              {report.name}
            </Text>
            <Text style={[styles.reportDate, { color: theme.colors.text + '80' }]}>
              {report.date}
            </Text>
          </View>
          
          <View style={styles.reportActions}>
            <Chip
              mode="outlined"
              style={{
                backgroundColor: getStatusColor(report.status) + '20',
                borderColor: getStatusColor(report.status)
              }}
              textStyle={{ color: getStatusColor(report.status) }}
            >
              {report.status}
            </Chip>
            
            <TouchableOpacity
              onPress={() => handleDeleteReport(report.id)}
              style={styles.deleteButton}
            >
              <Icon name="delete" size={20} color="#F44336" />
            </TouchableOpacity>
          </View>
        </View>

        <View style={styles.reportStats}>
          <View style={styles.statItem}>
            <Text style={[styles.statValue, { color: theme.colors.text }]}>
              {report.totalIssues}
            </Text>
            <Text style={[styles.statLabel, { color: theme.colors.text + '80' }]}>
              Total Issues
            </Text>
          </View>
          
          <View style={styles.statItem}>
            <Text style={[styles.statValue, { color: theme.colors.text }]}>
              {report.filesScanned}
            </Text>
            <Text style={[styles.statLabel, { color: theme.colors.text + '80' }]}>
              Files Scanned
            </Text>
          </View>
          
          <View style={styles.statItem}>
            <Text style={[styles.statValue, { color: theme.colors.text }]}>
              {Math.round(report.duration / 1000)}s
            </Text>
            <Text style={[styles.statLabel, { color: theme.colors.text + '80' }]}>
              Duration
            </Text>
          </View>
        </View>

        <View style={styles.severityBreakdown}>
          {report.criticalIssues > 0 && (
            <Chip
              mode="outlined"
              style={styles.severityChip}
              textStyle={{ color: getSeverityColor('critical') }}
            >
              {report.criticalIssues} Critical
            </Chip>
          )}
          {report.highIssues > 0 && (
            <Chip
              mode="outlined"
              style={styles.severityChip}
              textStyle={{ color: getSeverityColor('high') }}
            >
              {report.highIssues} High
            </Chip>
          )}
          {report.mediumIssues > 0 && (
            <Chip
              mode="outlined"
              style={styles.severityChip}
              textStyle={{ color: getSeverityColor('medium') }}
            >
              {report.mediumIssues} Medium
            </Chip>
          )}
          {report.lowIssues > 0 && (
            <Chip
              mode="outlined"
              style={styles.severityChip}
              textStyle={{ color: getSeverityColor('low') }}
            >
              {report.lowIssues} Low
            </Chip>
          )}
        </View>
      </Card.Content>
    </Card>
  );

  const renderFilterButtons = () => (
    <View style={styles.filterContainer}>
      <ScrollView horizontal showsHorizontalScrollIndicator={false}>
        {['all', 'completed', 'running', 'failed'].map((status) => (
          <TouchableOpacity
            key={status}
            style={[
              styles.filterButton,
              filterStatus === status && {
                backgroundColor: theme.colors.primary,
              }
            ]}
            onPress={() => setFilterStatus(status)}
          >
            <Text
              style={[
                styles.filterButtonText,
                {
                  color: filterStatus === status
                    ? 'white'
                    : theme.colors.text
                }
              ]}
            >
              {status.charAt(0).toUpperCase() + status.slice(1)}
            </Text>
          </TouchableOpacity>
        ))}
      </ScrollView>
    </View>
  );

  if (loading) {
    return (
      <View style={[styles.container, styles.centered, { backgroundColor: theme.colors.background }]}>
        <Icon name="file-document" size={48} color={theme.colors.text + '40'} />
        <Text style={[styles.loadingText, { color: theme.colors.text }]}>
          Loading reports...
        </Text>
      </View>
    );
  }

  return (
    <View style={[styles.container, { backgroundColor: theme.colors.background }]}>
      <Searchbar
        placeholder="Search reports..."
        onChangeText={setSearchQuery}
        value={searchQuery}
        style={styles.searchBar}
      />

      {renderFilterButtons()}

      <FlatList
        data={filteredReports}
        renderItem={renderReportCard}
        keyExtractor={(item) => item.id}
        refreshControl={
          <RefreshControl refreshing={refreshing} onRefresh={onRefresh} />
        }
        contentContainerStyle={styles.listContainer}
        ListEmptyComponent={
          <View style={styles.emptyState}>
            <Icon name="file-document-outline" size={64} color={theme.colors.text + '40'} />
            <Text style={[styles.emptyStateText, { color: theme.colors.text + '60' }]}>
              No reports found
            </Text>
            <Text style={[styles.emptyStateSubtext, { color: theme.colors.text + '40' }]}>
              Run a security scan to generate your first report
            </Text>
          </View>
        }
      />

      <FAB
        icon="plus"
        style={[styles.fab, { backgroundColor: theme.colors.primary }]}
        onPress={() => navigation.navigate('Scan')}
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  centered: {
    justifyContent: 'center',
    alignItems: 'center',
  },
  searchBar: {
    margin: 16,
    marginBottom: 8,
  },
  filterContainer: {
    paddingHorizontal: 16,
    paddingBottom: 16,
  },
  filterButton: {
    paddingHorizontal: 16,
    paddingVertical: 8,
    borderRadius: 20,
    marginRight: 8,
    borderWidth: 1,
    borderColor: '#E0E0E0',
  },
  filterButtonText: {
    fontSize: 14,
    fontWeight: '600',
  },
  listContainer: {
    padding: 16,
    paddingTop: 0,
  },
  reportCard: {
    marginBottom: 16,
    elevation: 4,
  },
  reportHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 16,
  },
  reportInfo: {
    flex: 1,
  },
  reportName: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 4,
  },
  reportDate: {
    fontSize: 14,
  },
  reportActions: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  deleteButton: {
    marginLeft: 8,
    padding: 4,
  },
  reportStats: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    marginBottom: 16,
    paddingVertical: 12,
    backgroundColor: 'rgba(255, 255, 255, 0.05)',
    borderRadius: 8,
  },
  statItem: {
    alignItems: 'center',
  },
  statValue: {
    fontSize: 20,
    fontWeight: 'bold',
    marginBottom: 2,
  },
  statLabel: {
    fontSize: 12,
  },
  severityBreakdown: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8,
  },
  severityChip: {
    marginRight: 4,
    marginBottom: 4,
  },
  emptyState: {
    alignItems: 'center',
    paddingVertical: 64,
  },
  emptyStateText: {
    fontSize: 18,
    fontWeight: '600',
    marginTop: 16,
    marginBottom: 8,
  },
  emptyStateSubtext: {
    fontSize: 14,
    textAlign: 'center',
  },
  loadingText: {
    marginTop: 16,
    fontSize: 16,
  },
  fab: {
    position: 'absolute',
    margin: 16,
    right: 0,
    bottom: 0,
  },
});

export default ReportsScreen;
