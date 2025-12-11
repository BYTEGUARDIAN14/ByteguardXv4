import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  Alert,
  TouchableOpacity,
  Animated,
  Dimensions
} from 'react-native';
import { Card, Button, ProgressBar, Chip, TextInput } from 'react-native-paper';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import DocumentPicker from 'react-native-document-picker';
import { useTheme } from '../context/ThemeContext';
import { SecurityService } from '../services/SecurityService';
import { NotificationService } from '../services/NotificationService';

const { width: screenWidth } = Dimensions.get('window');

interface ScanConfig {
  scanType: 'quick' | 'deep' | 'custom';
  targetPath: string;
  includePatterns: string[];
  excludePatterns: string[];
  scanners: {
    secrets: boolean;
    vulnerabilities: boolean;
    dependencies: boolean;
    codeQuality: boolean;
    compliance: boolean;
  };
}

interface ScanProgress {
  stage: string;
  progress: number;
  currentFile: string;
  filesScanned: number;
  totalFiles: number;
  issuesFound: number;
}

const ScanScreen: React.FC = () => {
  const { theme } = useTheme();
  const [scanConfig, setScanConfig] = useState<ScanConfig>({
    scanType: 'quick',
    targetPath: '',
    includePatterns: ['**/*.js', '**/*.ts', '**/*.py', '**/*.java'],
    excludePatterns: ['**/node_modules/**', '**/venv/**', '**/.git/**'],
    scanners: {
      secrets: true,
      vulnerabilities: true,
      dependencies: true,
      codeQuality: false,
      compliance: false,
    }
  });
  
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState<ScanProgress | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);
  const [animatedValue] = useState(new Animated.Value(0));

  useEffect(() => {
    if (isScanning) {
      startProgressAnimation();
    } else {
      stopProgressAnimation();
    }
  }, [isScanning]);

  const startProgressAnimation = () => {
    Animated.loop(
      Animated.sequence([
        Animated.timing(animatedValue, {
          toValue: 1,
          duration: 1000,
          useNativeDriver: true,
        }),
        Animated.timing(animatedValue, {
          toValue: 0,
          duration: 1000,
          useNativeDriver: true,
        }),
      ])
    ).start();
  };

  const stopProgressAnimation = () => {
    animatedValue.stopAnimation();
    animatedValue.setValue(0);
  };

  const selectDirectory = async () => {
    try {
      const result = await DocumentPicker.pickDirectory();
      if (result) {
        setScanConfig(prev => ({
          ...prev,
          targetPath: result.uri
        }));
      }
    } catch (error) {
      if (!DocumentPicker.isCancel(error)) {
        Alert.alert('Error', 'Failed to select directory');
      }
    }
  };

  const selectFiles = async () => {
    try {
      const results = await DocumentPicker.pick({
        type: [DocumentPicker.types.allFiles],
        allowMultiSelection: true,
      });
      
      if (results.length > 0) {
        const paths = results.map(file => file.uri).join(';');
        setScanConfig(prev => ({
          ...prev,
          targetPath: paths
        }));
      }
    } catch (error) {
      if (!DocumentPicker.isCancel(error)) {
        Alert.alert('Error', 'Failed to select files');
      }
    }
  };

  const updateScanType = (type: 'quick' | 'deep' | 'custom') => {
    let newConfig = { ...scanConfig, scanType: type };
    
    switch (type) {
      case 'quick':
        newConfig.scanners = {
          secrets: true,
          vulnerabilities: true,
          dependencies: false,
          codeQuality: false,
          compliance: false,
        };
        break;
      case 'deep':
        newConfig.scanners = {
          secrets: true,
          vulnerabilities: true,
          dependencies: true,
          codeQuality: true,
          compliance: true,
        };
        break;
      // custom keeps current settings
    }
    
    setScanConfig(newConfig);
  };

  const toggleScanner = (scanner: keyof ScanConfig['scanners']) => {
    setScanConfig(prev => ({
      ...prev,
      scanType: 'custom',
      scanners: {
        ...prev.scanners,
        [scanner]: !prev.scanners[scanner]
      }
    }));
  };

  const startScan = async () => {
    if (!scanConfig.targetPath) {
      Alert.alert('Error', 'Please select files or directory to scan');
      return;
    }

    try {
      setIsScanning(true);
      setScanProgress({
        stage: 'Initializing scan...',
        progress: 0,
        currentFile: '',
        filesScanned: 0,
        totalFiles: 0,
        issuesFound: 0
      });

      const result = await SecurityService.startScan(scanConfig);
      setScanId(result.scanId);

      // Start polling for progress
      pollScanProgress(result.scanId);

    } catch (error) {
      console.error('Failed to start scan:', error);
      Alert.alert('Error', 'Failed to start security scan');
      setIsScanning(false);
    }
  };

  const pollScanProgress = async (scanId: string) => {
    const pollInterval = setInterval(async () => {
      try {
        const progress = await SecurityService.getScanProgress(scanId);
        setScanProgress(progress);

        if (progress.progress >= 100) {
          clearInterval(pollInterval);
          setIsScanning(false);
          
          // Show completion notification
          NotificationService.showNotification(
            'Scan Complete',
            `Found ${progress.issuesFound} security issues`
          );
          
          // Navigate to results
          // navigation.navigate('ScanResults', { scanId });
        }
      } catch (error) {
        console.error('Failed to get scan progress:', error);
        clearInterval(pollInterval);
        setIsScanning(false);
        Alert.alert('Error', 'Scan failed or was interrupted');
      }
    }, 2000);
  };

  const stopScan = async () => {
    if (scanId) {
      try {
        await SecurityService.stopScan(scanId);
        setIsScanning(false);
        setScanProgress(null);
        setScanId(null);
      } catch (error) {
        console.error('Failed to stop scan:', error);
        Alert.alert('Error', 'Failed to stop scan');
      }
    }
  };

  const renderScanTypeSelector = () => (
    <Card style={styles.card}>
      <Card.Content>
        <Text style={[styles.cardTitle, { color: theme.colors.text }]}>
          Scan Type
        </Text>
        
        <View style={styles.scanTypeButtons}>
          {(['quick', 'deep', 'custom'] as const).map((type) => (
            <TouchableOpacity
              key={type}
              style={[
                styles.scanTypeButton,
                scanConfig.scanType === type && {
                  backgroundColor: theme.colors.primary,
                }
              ]}
              onPress={() => updateScanType(type)}
            >
              <Text
                style={[
                  styles.scanTypeButtonText,
                  {
                    color: scanConfig.scanType === type
                      ? 'white'
                      : theme.colors.text
                  }
                ]}
              >
                {type.charAt(0).toUpperCase() + type.slice(1)}
              </Text>
            </TouchableOpacity>
          ))}
        </View>
        
        <Text style={[styles.scanTypeDescription, { color: theme.colors.text + '80' }]}>
          {scanConfig.scanType === 'quick' && 'Fast scan for critical vulnerabilities and secrets'}
          {scanConfig.scanType === 'deep' && 'Comprehensive scan including all security checks'}
          {scanConfig.scanType === 'custom' && 'Customizable scan with selected security checks'}
        </Text>
      </Card.Content>
    </Card>
  );

  const renderTargetSelection = () => (
    <Card style={styles.card}>
      <Card.Content>
        <Text style={[styles.cardTitle, { color: theme.colors.text }]}>
          Scan Target
        </Text>
        
        <View style={styles.targetButtons}>
          <Button
            mode="outlined"
            onPress={selectDirectory}
            icon="folder"
            style={styles.targetButton}
          >
            Select Directory
          </Button>
          
          <Button
            mode="outlined"
            onPress={selectFiles}
            icon="file-multiple"
            style={styles.targetButton}
          >
            Select Files
          </Button>
        </View>
        
        {scanConfig.targetPath && (
          <View style={styles.selectedPath}>
            <Icon name="check-circle" size={16} color="#4CAF50" />
            <Text style={[styles.pathText, { color: theme.colors.text }]}>
              {scanConfig.targetPath.length > 50
                ? '...' + scanConfig.targetPath.slice(-47)
                : scanConfig.targetPath}
            </Text>
          </View>
        )}
      </Card.Content>
    </Card>
  );

  const renderScannerOptions = () => (
    <Card style={styles.card}>
      <Card.Content>
        <Text style={[styles.cardTitle, { color: theme.colors.text }]}>
          Security Checks
        </Text>
        
        {Object.entries(scanConfig.scanners).map(([key, enabled]) => (
          <TouchableOpacity
            key={key}
            style={styles.scannerOption}
            onPress={() => toggleScanner(key as keyof ScanConfig['scanners'])}
          >
            <View style={styles.scannerInfo}>
              <Icon
                name={getScannerIcon(key)}
                size={24}
                color={enabled ? theme.colors.primary : theme.colors.text + '60'}
              />
              <View style={styles.scannerText}>
                <Text style={[styles.scannerName, { color: theme.colors.text }]}>
                  {getScannerName(key)}
                </Text>
                <Text style={[styles.scannerDescription, { color: theme.colors.text + '80' }]}>
                  {getScannerDescription(key)}
                </Text>
              </View>
            </View>
            <Icon
              name={enabled ? 'toggle-switch' : 'toggle-switch-off'}
              size={24}
              color={enabled ? theme.colors.primary : theme.colors.text + '60'}
            />
          </TouchableOpacity>
        ))}
      </Card.Content>
    </Card>
  );

  const renderScanProgress = () => {
    if (!isScanning || !scanProgress) return null;

    return (
      <Card style={styles.card}>
        <Card.Content>
          <View style={styles.progressHeader}>
            <Text style={[styles.cardTitle, { color: theme.colors.text }]}>
              Scanning in Progress
            </Text>
            <Animated.View
              style={{
                opacity: animatedValue,
              }}
            >
              <Icon name="shield-search" size={24} color={theme.colors.primary} />
            </Animated.View>
          </View>
          
          <ProgressBar
            progress={scanProgress.progress / 100}
            color={theme.colors.primary}
            style={styles.progressBar}
          />
          
          <Text style={[styles.progressText, { color: theme.colors.text }]}>
            {scanProgress.stage}
          </Text>
          
          {scanProgress.currentFile && (
            <Text style={[styles.currentFile, { color: theme.colors.text + '80' }]}>
              {scanProgress.currentFile}
            </Text>
          )}
          
          <View style={styles.progressStats}>
            <Text style={[styles.progressStat, { color: theme.colors.text }]}>
              Files: {scanProgress.filesScanned}/{scanProgress.totalFiles}
            </Text>
            <Text style={[styles.progressStat, { color: theme.colors.text }]}>
              Issues: {scanProgress.issuesFound}
            </Text>
          </View>
          
          <Button
            mode="outlined"
            onPress={stopScan}
            icon="stop"
            style={styles.stopButton}
          >
            Stop Scan
          </Button>
        </Card.Content>
      </Card>
    );
  };

  const getScannerIcon = (scanner: string) => {
    switch (scanner) {
      case 'secrets': return 'key';
      case 'vulnerabilities': return 'shield-alert';
      case 'dependencies': return 'package-variant';
      case 'codeQuality': return 'code-tags';
      case 'compliance': return 'clipboard-check';
      default: return 'shield';
    }
  };

  const getScannerName = (scanner: string) => {
    switch (scanner) {
      case 'secrets': return 'Secret Detection';
      case 'vulnerabilities': return 'Vulnerability Scan';
      case 'dependencies': return 'Dependency Check';
      case 'codeQuality': return 'Code Quality';
      case 'compliance': return 'Compliance Check';
      default: return scanner;
    }
  };

  const getScannerDescription = (scanner: string) => {
    switch (scanner) {
      case 'secrets': return 'Detect API keys, passwords, and tokens';
      case 'vulnerabilities': return 'Find known security vulnerabilities';
      case 'dependencies': return 'Check for vulnerable dependencies';
      case 'codeQuality': return 'Analyze code quality and patterns';
      case 'compliance': return 'Check compliance with security standards';
      default: return '';
    }
  };

  return (
    <ScrollView
      style={[styles.container, { backgroundColor: theme.colors.background }]}
    >
      {renderScanTypeSelector()}
      {renderTargetSelection()}
      {renderScannerOptions()}
      {renderScanProgress()}
      
      {!isScanning && (
        <Button
          mode="contained"
          onPress={startScan}
          icon="shield-search"
          style={styles.startButton}
          disabled={!scanConfig.targetPath}
        >
          Start Security Scan
        </Button>
      )}
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 16,
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
  scanTypeButtons: {
    flexDirection: 'row',
    marginBottom: 12,
  },
  scanTypeButton: {
    flex: 1,
    padding: 12,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#E0E0E0',
    marginHorizontal: 4,
    alignItems: 'center',
  },
  scanTypeButtonText: {
    fontWeight: '600',
  },
  scanTypeDescription: {
    fontSize: 14,
    fontStyle: 'italic',
  },
  targetButtons: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 12,
  },
  targetButton: {
    flex: 1,
    marginHorizontal: 4,
  },
  selectedPath: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: 8,
    backgroundColor: '#E8F5E8',
    borderRadius: 4,
  },
  pathText: {
    marginLeft: 8,
    fontSize: 14,
  },
  scannerOption: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderBottomColor: '#E0E0E0',
  },
  scannerInfo: {
    flexDirection: 'row',
    alignItems: 'center',
    flex: 1,
  },
  scannerText: {
    marginLeft: 12,
    flex: 1,
  },
  scannerName: {
    fontSize: 16,
    fontWeight: '600',
    marginBottom: 2,
  },
  scannerDescription: {
    fontSize: 14,
  },
  progressHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 16,
  },
  progressBar: {
    height: 8,
    borderRadius: 4,
    marginBottom: 12,
  },
  progressText: {
    fontSize: 16,
    fontWeight: '600',
    marginBottom: 4,
  },
  currentFile: {
    fontSize: 14,
    marginBottom: 12,
  },
  progressStats: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 16,
  },
  progressStat: {
    fontSize: 14,
    fontWeight: '600',
  },
  stopButton: {
    marginTop: 8,
  },
  startButton: {
    marginVertical: 16,
    paddingVertical: 8,
  },
});

export default ScanScreen;
