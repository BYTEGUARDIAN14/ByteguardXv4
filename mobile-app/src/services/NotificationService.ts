import * as Notifications from 'expo-notifications';
import * as Device from 'expo-device';
import { Platform } from 'react-native';
import * as SecureStore from 'expo-secure-store';

export interface NotificationData {
  title: string;
  body: string;
  data?: any;
  categoryId?: string;
  sound?: boolean;
  priority?: 'min' | 'low' | 'default' | 'high' | 'max';
}

export interface ScheduledNotification {
  id: string;
  title: string;
  body: string;
  trigger: Date | number;
  data?: any;
}

class NotificationServiceClass {
  private isInitialized = false;
  private pushToken: string | null = null;

  async initialize(): Promise<void> {
    if (this.isInitialized) return;

    try {
      // Configure notification behavior
      Notifications.setNotificationHandler({
        handleNotification: async () => ({
          shouldShowAlert: true,
          shouldPlaySound: true,
          shouldSetBadge: true,
        }),
      });

      // Set up notification categories
      await this.setupNotificationCategories();

      // Request permissions and get push token
      await this.requestPermissions();
      
      this.isInitialized = true;
    } catch (error) {
      console.error('Failed to initialize notification service:', error);
    }
  }

  private async setupNotificationCategories(): Promise<void> {
    try {
      await Notifications.setNotificationCategoryAsync('scan_complete', [
        {
          identifier: 'view_results',
          buttonTitle: 'View Results',
          options: {
            opensAppToForeground: true,
          },
        },
        {
          identifier: 'dismiss',
          buttonTitle: 'Dismiss',
          options: {
            opensAppToForeground: false,
          },
        },
      ]);

      await Notifications.setNotificationCategoryAsync('security_alert', [
        {
          identifier: 'view_details',
          buttonTitle: 'View Details',
          options: {
            opensAppToForeground: true,
          },
        },
        {
          identifier: 'mark_resolved',
          buttonTitle: 'Mark Resolved',
          options: {
            opensAppToForeground: false,
          },
        },
      ]);
    } catch (error) {
      console.error('Failed to setup notification categories:', error);
    }
  }

  async requestPermissions(): Promise<boolean> {
    try {
      if (!Device.isDevice) {
        console.warn('Push notifications only work on physical devices');
        return false;
      }

      const { status: existingStatus } = await Notifications.getPermissionsAsync();
      let finalStatus = existingStatus;

      if (existingStatus !== 'granted') {
        const { status } = await Notifications.requestPermissionsAsync();
        finalStatus = status;
      }

      if (finalStatus !== 'granted') {
        console.warn('Push notification permissions not granted');
        return false;
      }

      // Get push token
      const token = await Notifications.getExpoPushTokenAsync({
        projectId: process.env.EXPO_PUBLIC_PROJECT_ID,
      });
      
      this.pushToken = token.data;
      
      // Store token securely
      await SecureStore.setItemAsync('push_token', this.pushToken);

      // Configure Android channel
      if (Platform.OS === 'android') {
        await Notifications.setNotificationChannelAsync('default', {
          name: 'ByteGuardX Notifications',
          importance: Notifications.AndroidImportance.MAX,
          vibrationPattern: [0, 250, 250, 250],
          lightColor: '#0ea5e9',
          sound: 'default',
        });

        await Notifications.setNotificationChannelAsync('security_alerts', {
          name: 'Security Alerts',
          importance: Notifications.AndroidImportance.HIGH,
          vibrationPattern: [0, 500, 250, 500],
          lightColor: '#f44336',
          sound: 'default',
        });
      }

      return true;
    } catch (error) {
      console.error('Failed to request notification permissions:', error);
      return false;
    }
  }

  async showNotification(notification: NotificationData): Promise<string | null> {
    try {
      const notificationId = await Notifications.scheduleNotificationAsync({
        content: {
          title: notification.title,
          body: notification.body,
          data: notification.data || {},
          categoryIdentifier: notification.categoryId,
          sound: notification.sound !== false,
          priority: this.mapPriority(notification.priority || 'default'),
        },
        trigger: null, // Show immediately
      });

      return notificationId;
    } catch (error) {
      console.error('Failed to show notification:', error);
      return null;
    }
  }

  async scheduleNotification(notification: ScheduledNotification): Promise<string | null> {
    try {
      const trigger = typeof notification.trigger === 'number' 
        ? { seconds: notification.trigger }
        : notification.trigger;

      const notificationId = await Notifications.scheduleNotificationAsync({
        content: {
          title: notification.title,
          body: notification.body,
          data: notification.data || {},
        },
        trigger,
      });

      return notificationId;
    } catch (error) {
      console.error('Failed to schedule notification:', error);
      return null;
    }
  }

  async cancelNotification(notificationId: string): Promise<void> {
    try {
      await Notifications.cancelScheduledNotificationAsync(notificationId);
    } catch (error) {
      console.error('Failed to cancel notification:', error);
    }
  }

  async cancelAllNotifications(): Promise<void> {
    try {
      await Notifications.cancelAllScheduledNotificationsAsync();
    } catch (error) {
      console.error('Failed to cancel all notifications:', error);
    }
  }

  async getBadgeCount(): Promise<number> {
    try {
      return await Notifications.getBadgeCountAsync();
    } catch (error) {
      console.error('Failed to get badge count:', error);
      return 0;
    }
  }

  async setBadgeCount(count: number): Promise<void> {
    try {
      await Notifications.setBadgeCountAsync(count);
    } catch (error) {
      console.error('Failed to set badge count:', error);
    }
  }

  async clearBadge(): Promise<void> {
    try {
      await Notifications.setBadgeCountAsync(0);
    } catch (error) {
      console.error('Failed to clear badge:', error);
    }
  }

  // Convenience methods for common notifications
  async notifyScanComplete(scanId: string, issuesFound: number): Promise<void> {
    const title = 'Security Scan Complete';
    const body = issuesFound > 0 
      ? `Found ${issuesFound} security ${issuesFound === 1 ? 'issue' : 'issues'}`
      : 'No security issues found';

    await this.showNotification({
      title,
      body,
      categoryId: 'scan_complete',
      data: { scanId, type: 'scan_complete' },
      priority: issuesFound > 0 ? 'high' : 'default',
    });
  }

  async notifySecurityAlert(severity: string, title: string, description: string): Promise<void> {
    await this.showNotification({
      title: `${severity.toUpperCase()} Security Alert`,
      body: `${title}: ${description}`,
      categoryId: 'security_alert',
      data: { type: 'security_alert', severity },
      priority: severity === 'critical' ? 'max' : 'high',
    });
  }

  async notifyWeeklyReport(totalScans: number, issuesResolved: number): Promise<void> {
    await this.showNotification({
      title: 'Weekly Security Report',
      body: `${totalScans} scans completed, ${issuesResolved} issues resolved this week`,
      data: { type: 'weekly_report' },
      priority: 'default',
    });
  }

  async scheduleWeeklyReport(): Promise<void> {
    // Schedule weekly report for every Sunday at 9 AM
    const now = new Date();
    const nextSunday = new Date(now);
    nextSunday.setDate(now.getDate() + (7 - now.getDay()));
    nextSunday.setHours(9, 0, 0, 0);

    await this.scheduleNotification({
      id: 'weekly_report',
      title: 'Weekly Security Report',
      body: 'Your weekly security summary is ready',
      trigger: nextSunday,
      data: { type: 'weekly_report' },
    });
  }

  // Push token management
  getPushToken(): string | null {
    return this.pushToken;
  }

  async refreshPushToken(): Promise<string | null> {
    try {
      if (!Device.isDevice) return null;

      const token = await Notifications.getExpoPushTokenAsync({
        projectId: process.env.EXPO_PUBLIC_PROJECT_ID,
      });
      
      this.pushToken = token.data;
      await SecureStore.setItemAsync('push_token', this.pushToken);
      
      return this.pushToken;
    } catch (error) {
      console.error('Failed to refresh push token:', error);
      return null;
    }
  }

  // Notification listeners
  addNotificationReceivedListener(listener: (notification: Notifications.Notification) => void) {
    return Notifications.addNotificationReceivedListener(listener);
  }

  addNotificationResponseReceivedListener(
    listener: (response: Notifications.NotificationResponse) => void
  ) {
    return Notifications.addNotificationResponseReceivedListener(listener);
  }

  // Helper methods
  private mapPriority(priority: string): Notifications.AndroidNotificationPriority {
    switch (priority) {
      case 'min': return Notifications.AndroidNotificationPriority.MIN;
      case 'low': return Notifications.AndroidNotificationPriority.LOW;
      case 'high': return Notifications.AndroidNotificationPriority.HIGH;
      case 'max': return Notifications.AndroidNotificationPriority.MAX;
      default: return Notifications.AndroidNotificationPriority.DEFAULT;
    }
  }

  async getNotificationSettings(): Promise<any> {
    try {
      const settings = await Notifications.getPermissionsAsync();
      return {
        granted: settings.status === 'granted',
        canAskAgain: settings.canAskAgain,
        ios: settings.ios,
        android: settings.android,
      };
    } catch (error) {
      console.error('Failed to get notification settings:', error);
      return null;
    }
  }

  async openNotificationSettings(): Promise<void> {
    try {
      if (Platform.OS === 'ios') {
        // On iOS, we can't directly open notification settings
        // The user needs to go to Settings > Notifications > App Name
        console.log('Please go to Settings > Notifications > ByteGuardX to manage notification settings');
      } else {
        // On Android, we can open the app's notification settings
        await Notifications.openSettingsAsync();
      }
    } catch (error) {
      console.error('Failed to open notification settings:', error);
    }
  }
}

export const NotificationService = new NotificationServiceClass();
