import React, { useEffect, useState } from 'react';
import { StatusBar } from 'expo-status-bar';
import { NavigationContainer } from '@react-navigation/native';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { createStackNavigator } from '@react-navigation/stack';
import { Provider as PaperProvider, MD3DarkTheme } from 'react-native-paper';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import Icon from 'react-native-vector-icons/MaterialCommunityIcons';

// Screens
import HomeScreen from './src/screens/HomeScreen';
import ScanScreen from './src/screens/ScanScreen';
import ReportsScreen from './src/screens/ReportsScreen';
import SettingsScreen from './src/screens/SettingsScreen';
import LoginScreen from './src/screens/LoginScreen';
import ScanResultsScreen from './src/screens/ScanResultsScreen';
import ReportDetailScreen from './src/screens/ReportDetailScreen';

// Context
import { AuthProvider, useAuth } from './src/context/AuthContext';
import { ThemeProvider } from './src/context/ThemeContext';

// Services
import { NotificationService } from './src/services/NotificationService';

const Tab = createBottomTabNavigator();
const Stack = createStackNavigator();

// Custom theme matching ByteGuardX design
const theme = {
  ...MD3DarkTheme,
  colors: {
    ...MD3DarkTheme.colors,
    primary: '#0ea5e9',
    primaryContainer: '#0284c7',
    secondary: '#64748b',
    background: '#000000',
    surface: '#18181b',
    surfaceVariant: '#27272a',
    onSurface: '#fafafa',
    onSurfaceVariant: '#d4d4d8',
  },
};

function TabNavigator() {
  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        tabBarIcon: ({ focused, color, size }) => {
          let iconName: string;

          switch (route.name) {
            case 'Home':
              iconName = focused ? 'home' : 'home-outline';
              break;
            case 'Scan':
              iconName = focused ? 'shield-search' : 'shield-search-outline';
              break;
            case 'Reports':
              iconName = focused ? 'file-document' : 'file-document-outline';
              break;
            case 'Settings':
              iconName = focused ? 'cog' : 'cog-outline';
              break;
            default:
              iconName = 'circle';
          }

          return <Icon name={iconName} size={size} color={color} />;
        },
        tabBarActiveTintColor: '#0ea5e9',
        tabBarInactiveTintColor: '#64748b',
        tabBarStyle: {
          backgroundColor: '#18181b',
          borderTopColor: '#27272a',
        },
        headerStyle: {
          backgroundColor: '#000000',
        },
        headerTintColor: '#fafafa',
        headerTitleStyle: {
          fontWeight: 'bold',
        },
      })}
    >
      <Tab.Screen 
        name="Home" 
        component={HomeScreen}
        options={{ title: 'Dashboard' }}
      />
      <Tab.Screen 
        name="Scan" 
        component={ScanScreen}
        options={{ title: 'Security Scan' }}
      />
      <Tab.Screen 
        name="Reports" 
        component={ReportsScreen}
        options={{ title: 'Reports' }}
      />
      <Tab.Screen 
        name="Settings" 
        component={SettingsScreen}
        options={{ title: 'Settings' }}
      />
    </Tab.Navigator>
  );
}

function AppNavigator() {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return null; // Show loading screen
  }

  return (
    <NavigationContainer theme={{
      dark: true,
      colors: {
        primary: '#0ea5e9',
        background: '#000000',
        card: '#18181b',
        text: '#fafafa',
        border: '#27272a',
        notification: '#0ea5e9',
      },
    }}>
      <Stack.Navigator
        screenOptions={{
          headerStyle: {
            backgroundColor: '#000000',
          },
          headerTintColor: '#fafafa',
          headerTitleStyle: {
            fontWeight: 'bold',
          },
        }}
      >
        {!isAuthenticated ? (
          <Stack.Screen 
            name="Login" 
            component={LoginScreen}
            options={{ headerShown: false }}
          />
        ) : (
          <>
            <Stack.Screen 
              name="Main" 
              component={TabNavigator}
              options={{ headerShown: false }}
            />
            <Stack.Screen 
              name="ScanResults" 
              component={ScanResultsScreen}
              options={{ title: 'Scan Results' }}
            />
            <Stack.Screen 
              name="ReportDetail" 
              component={ReportDetailScreen}
              options={{ title: 'Report Details' }}
            />
          </>
        )}
      </Stack.Navigator>
    </NavigationContainer>
  );
}

export default function App() {
  const [isReady, setIsReady] = useState(false);

  useEffect(() => {
    async function prepare() {
      try {
        // Initialize notification service
        await NotificationService.initialize();
        
        // Any other initialization
        await new Promise(resolve => setTimeout(resolve, 1000));
      } catch (e) {
        console.warn(e);
      } finally {
        setIsReady(true);
      }
    }

    prepare();
  }, []);

  if (!isReady) {
    return null; // Show splash screen
  }

  return (
    <SafeAreaProvider>
      <PaperProvider theme={theme}>
        <ThemeProvider>
          <AuthProvider>
            <AppNavigator />
            <StatusBar style="light" backgroundColor="#000000" />
          </AuthProvider>
        </ThemeProvider>
      </PaperProvider>
    </SafeAreaProvider>
  );
}
