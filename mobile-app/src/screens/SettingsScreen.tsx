import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  Alert,
  Switch,
  TouchableOpacity
} from 'react-native';
import {
  Card,
  Button,
  TextInput,
  Divider,
  List,
  Dialog,
  Portal,
  RadioButton
} from 'react-native-paper';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import { SecurityService } from '../services/SecurityService';
import { NotificationService } from '../services/NotificationService';

interface UserSettings {
  notifications: {
    scanComplete: boolean;
    securityAlerts: boolean;
    weeklyReports: boolean;
    pushNotifications: boolean;
  };
  scanning: {
    autoScanOnSave: boolean;
    includeTests: boolean;
    maxFileSize: number;
    scanTimeout: number;
  };
  privacy: {
    shareAnonymousData: boolean;
    enableAnalytics: boolean;
  };
  appearance: {
    theme: 'dark' | 'light' | 'auto';
    compactMode: boolean;
  };
}

const SettingsScreen: React.FC = () => {
  const { user, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const [settings, setSettings] = useState<UserSettings>({
    notifications: {
      scanComplete: true,
      securityAlerts: true,
      weeklyReports: false,
      pushNotifications: true,
    },
    scanning: {
      autoScanOnSave: false,
      includeTests: true,
      maxFileSize: 10,
      scanTimeout: 300,
    },
    privacy: {
      shareAnonymousData: false,
      enableAnalytics: false,
    },
    appearance: {
      theme: 'dark',
      compactMode: false,
    },
  });

  const [loading, setLoading] = useState(false);
  const [showLogoutDialog, setShowLogoutDialog] = useState(false);
  const [showThemeDialog, setShowThemeDialog] = useState(false);

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      const userSettings = await SecurityService.getUserSettings();
      if (userSettings) {
        setSettings(userSettings);
      }
    } catch (error) {
      console.error('Failed to load settings:', error);
    }
  };

  const saveSettings = async (newSettings: UserSettings) => {
    try {
      setLoading(true);
      await SecurityService.updateUserSettings(newSettings);
      setSettings(newSettings);
    } catch (error) {
      console.error('Failed to save settings:', error);
      Alert.alert('Error', 'Failed to save settings');
    } finally {
      setLoading(false);
    }
  };

  const updateSetting = (category: keyof UserSettings, key: string, value: any) => {
    const newSettings = {
      ...settings,
      [category]: {
        ...settings[category],
        [key]: value,
      },
    };
    setSettings(newSettings);
    saveSettings(newSettings);
  };

  const handleLogout = () => {
    setShowLogoutDialog(true);
  };

  const confirmLogout = async () => {
    try {
      await logout();
      setShowLogoutDialog(false);
    } catch (error) {
      Alert.alert('Error', 'Failed to logout');
    }
  };

  const handleExportData = async () => {
    try {
      Alert.alert(
        'Export Data',
        'Your data export will be prepared and sent to your email address.',
        [
          { text: 'Cancel', style: 'cancel' },
          {
            text: 'Export',
            onPress: async () => {
              await SecurityService.exportUserData();
              Alert.alert('Success', 'Data export initiated. You will receive an email shortly.');
            }
          }
        ]
      );
    } catch (error) {
      Alert.alert('Error', 'Failed to export data');
    }
  };

  const handleDeleteAccount = () => {
    Alert.alert(
      'Delete Account',
      'This action cannot be undone. All your data will be permanently deleted.',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Delete',
          style: 'destructive',
          onPress: () => {
            Alert.alert(
              'Are you sure?',
              'Type "DELETE" to confirm account deletion',
              [
                { text: 'Cancel', style: 'cancel' },
                {
                  text: 'Confirm',
                  style: 'destructive',
                  onPress: async () => {
                    try {
                      await SecurityService.deleteAccount();
                      await logout();
                    } catch (error) {
                      Alert.alert('Error', 'Failed to delete account');
                    }
                  }
                }
              ]
            );
          }
        }
      ]
    );
  };

  const renderSettingItem = (
    title: string,
    subtitle: string,
    value: boolean,
    onValueChange: (value: boolean) => void,
    icon: string
  ) => (
    <List.Item
      title={title}
      description={subtitle}
      left={(props) => <List.Icon {...props} icon={icon} />}
      right={() => (
        <Switch
          value={value}
          onValueChange={onValueChange}
          color={theme.colors.primary}
        />
      )}
    />
  );

  return (
    <ScrollView style={[styles.container, { backgroundColor: theme.colors.background }]}>
      {/* User Profile Section */}
      <Card style={styles.card}>
        <Card.Content>
          <View style={styles.profileSection}>
            <View style={styles.avatar}>
              <Icon name="account" size={40} color={theme.colors.primary} />
            </View>
            <View style={styles.profileInfo}>
              <Text style={[styles.userName, { color: theme.colors.text }]}>
                {user?.username || 'User'}
              </Text>
              <Text style={[styles.userEmail, { color: theme.colors.text + '80' }]}>
                {user?.email || 'user@example.com'}
              </Text>
            </View>
          </View>
        </Card.Content>
      </Card>

      {/* Notifications Settings */}
      <Card style={styles.card}>
        <Card.Content>
          <Text style={[styles.sectionTitle, { color: theme.colors.text }]}>
            Notifications
          </Text>
          
          {renderSettingItem(
            'Scan Complete',
            'Notify when security scans finish',
            settings.notifications.scanComplete,
            (value) => updateSetting('notifications', 'scanComplete', value),
            'check-circle'
          )}
          
          {renderSettingItem(
            'Security Alerts',
            'Critical security issue notifications',
            settings.notifications.securityAlerts,
            (value) => updateSetting('notifications', 'securityAlerts', value),
            'shield-alert'
          )}
          
          {renderSettingItem(
            'Weekly Reports',
            'Weekly security summary emails',
            settings.notifications.weeklyReports,
            (value) => updateSetting('notifications', 'weeklyReports', value),
            'email'
          )}
          
          {renderSettingItem(
            'Push Notifications',
            'Enable mobile push notifications',
            settings.notifications.pushNotifications,
            (value) => updateSetting('notifications', 'pushNotifications', value),
            'bell'
          )}
        </Card.Content>
      </Card>

      {/* Scanning Settings */}
      <Card style={styles.card}>
        <Card.Content>
          <Text style={[styles.sectionTitle, { color: theme.colors.text }]}>
            Scanning
          </Text>
          
          {renderSettingItem(
            'Auto-scan on Save',
            'Automatically scan files when saved',
            settings.scanning.autoScanOnSave,
            (value) => updateSetting('scanning', 'autoScanOnSave', value),
            'auto-fix'
          )}
          
          {renderSettingItem(
            'Include Test Files',
            'Scan test and spec files',
            settings.scanning.includeTests,
            (value) => updateSetting('scanning', 'includeTests', value),
            'test-tube'
          )}
          
          <List.Item
            title="Max File Size (MB)"
            description={`Currently: ${settings.scanning.maxFileSize}MB`}
            left={(props) => <List.Icon {...props} icon="file-document" />}
            right={() => (
              <TextInput
                value={settings.scanning.maxFileSize.toString()}
                onChangeText={(text) => {
                  const value = parseInt(text) || 10;
                  updateSetting('scanning', 'maxFileSize', value);
                }}
                keyboardType="numeric"
                style={styles.numberInput}
                mode="outlined"
              />
            )}
          />
        </Card.Content>
      </Card>

      {/* Privacy Settings */}
      <Card style={styles.card}>
        <Card.Content>
          <Text style={[styles.sectionTitle, { color: theme.colors.text }]}>
            Privacy
          </Text>
          
          {renderSettingItem(
            'Share Anonymous Data',
            'Help improve ByteGuardX with usage data',
            settings.privacy.shareAnonymousData,
            (value) => updateSetting('privacy', 'shareAnonymousData', value),
            'chart-line'
          )}
          
          {renderSettingItem(
            'Enable Analytics',
            'Track app usage for better experience',
            settings.privacy.enableAnalytics,
            (value) => updateSetting('privacy', 'enableAnalytics', value),
            'google-analytics'
          )}
        </Card.Content>
      </Card>

      {/* Appearance Settings */}
      <Card style={styles.card}>
        <Card.Content>
          <Text style={[styles.sectionTitle, { color: theme.colors.text }]}>
            Appearance
          </Text>
          
          <List.Item
            title="Theme"
            description={`Current: ${settings.appearance.theme}`}
            left={(props) => <List.Icon {...props} icon="palette" />}
            onPress={() => setShowThemeDialog(true)}
          />
          
          {renderSettingItem(
            'Compact Mode',
            'Show more content in less space',
            settings.appearance.compactMode,
            (value) => updateSetting('appearance', 'compactMode', value),
            'view-compact'
          )}
        </Card.Content>
      </Card>

      {/* Account Actions */}
      <Card style={styles.card}>
        <Card.Content>
          <Text style={[styles.sectionTitle, { color: theme.colors.text }]}>
            Account
          </Text>
          
          <List.Item
            title="Export Data"
            description="Download your data"
            left={(props) => <List.Icon {...props} icon="download" />}
            onPress={handleExportData}
          />
          
          <List.Item
            title="Logout"
            description="Sign out of your account"
            left={(props) => <List.Icon {...props} icon="logout" />}
            onPress={handleLogout}
          />
          
          <List.Item
            title="Delete Account"
            description="Permanently delete your account"
            left={(props) => <List.Icon {...props} icon="delete" color="#F44336" />}
            titleStyle={{ color: '#F44336' }}
            onPress={handleDeleteAccount}
          />
        </Card.Content>
      </Card>

      {/* Logout Confirmation Dialog */}
      <Portal>
        <Dialog visible={showLogoutDialog} onDismiss={() => setShowLogoutDialog(false)}>
          <Dialog.Title>Logout</Dialog.Title>
          <Dialog.Content>
            <Text>Are you sure you want to logout?</Text>
          </Dialog.Content>
          <Dialog.Actions>
            <Button onPress={() => setShowLogoutDialog(false)}>Cancel</Button>
            <Button onPress={confirmLogout}>Logout</Button>
          </Dialog.Actions>
        </Dialog>
      </Portal>

      {/* Theme Selection Dialog */}
      <Portal>
        <Dialog visible={showThemeDialog} onDismiss={() => setShowThemeDialog(false)}>
          <Dialog.Title>Select Theme</Dialog.Title>
          <Dialog.Content>
            <RadioButton.Group
              onValueChange={(value) => {
                updateSetting('appearance', 'theme', value);
                setShowThemeDialog(false);
              }}
              value={settings.appearance.theme}
            >
              <RadioButton.Item label="Dark" value="dark" />
              <RadioButton.Item label="Light" value="light" />
              <RadioButton.Item label="Auto" value="auto" />
            </RadioButton.Group>
          </Dialog.Content>
          <Dialog.Actions>
            <Button onPress={() => setShowThemeDialog(false)}>Cancel</Button>
          </Dialog.Actions>
        </Dialog>
      </Portal>
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
  profileSection: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  avatar: {
    width: 60,
    height: 60,
    borderRadius: 30,
    backgroundColor: 'rgba(14, 165, 233, 0.1)',
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 16,
  },
  profileInfo: {
    flex: 1,
  },
  userName: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 4,
  },
  userEmail: {
    fontSize: 14,
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    marginBottom: 8,
  },
  numberInput: {
    width: 80,
    height: 40,
  },
});

export default SettingsScreen;
