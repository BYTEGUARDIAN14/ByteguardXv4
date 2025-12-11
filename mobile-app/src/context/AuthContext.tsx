import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import * as SecureStore from 'expo-secure-store';
import axios, { AxiosResponse } from 'axios';
import { Alert } from 'react-native';

export interface User {
  id: string;
  email: string;
  username: string;
  role: string;
  subscriptionTier: string;
  organizationId?: string;
  preferences: any;
}

export interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<boolean>;
  logout: () => Promise<void>;
  register: (email: string, username: string, password: string) => Promise<boolean>;
  refreshToken: () => Promise<boolean>;
  updateProfile: (updates: Partial<User>) => Promise<boolean>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  const baseURL = process.env.EXPO_PUBLIC_API_URL || 'https://api.byteguardx.com';

  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    try {
      setIsLoading(true);
      
      const token = await SecureStore.getItemAsync('auth_token');
      if (!token) {
        setIsLoading(false);
        return;
      }

      // Verify token with server
      const response = await axios.get(`${baseURL}/api/auth/verify`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (response.data.valid) {
        setUser(response.data.user);
        setIsAuthenticated(true);
      } else {
        // Token is invalid, remove it
        await SecureStore.deleteItemAsync('auth_token');
        await SecureStore.deleteItemAsync('refresh_token');
      }
    } catch (error) {
      console.error('Auth check failed:', error);
      // Clear invalid tokens
      await SecureStore.deleteItemAsync('auth_token');
      await SecureStore.deleteItemAsync('refresh_token');
    } finally {
      setIsLoading(false);
    }
  };

  const login = async (email: string, password: string): Promise<boolean> => {
    try {
      setIsLoading(true);

      const response: AxiosResponse<{
        access_token: string;
        refresh_token: string;
        user: User;
      }> = await axios.post(`${baseURL}/api/auth/login`, {
        email,
        password,
      });

      const { access_token, refresh_token, user: userData } = response.data;

      // Store tokens securely
      await SecureStore.setItemAsync('auth_token', access_token);
      await SecureStore.setItemAsync('refresh_token', refresh_token);

      setUser(userData);
      setIsAuthenticated(true);

      return true;
    } catch (error: any) {
      console.error('Login failed:', error);
      
      let errorMessage = 'Login failed. Please try again.';
      if (error.response?.status === 401) {
        errorMessage = 'Invalid email or password.';
      } else if (error.response?.status === 429) {
        errorMessage = 'Too many login attempts. Please try again later.';
      } else if (error.response?.data?.error) {
        errorMessage = error.response.data.error;
      }

      Alert.alert('Login Error', errorMessage);
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (email: string, username: string, password: string): Promise<boolean> => {
    try {
      setIsLoading(true);

      const response: AxiosResponse<{
        access_token: string;
        refresh_token: string;
        user: User;
      }> = await axios.post(`${baseURL}/api/auth/register`, {
        email,
        username,
        password,
      });

      const { access_token, refresh_token, user: userData } = response.data;

      // Store tokens securely
      await SecureStore.setItemAsync('auth_token', access_token);
      await SecureStore.setItemAsync('refresh_token', refresh_token);

      setUser(userData);
      setIsAuthenticated(true);

      return true;
    } catch (error: any) {
      console.error('Registration failed:', error);
      
      let errorMessage = 'Registration failed. Please try again.';
      if (error.response?.status === 409) {
        errorMessage = 'Email or username already exists.';
      } else if (error.response?.data?.error) {
        errorMessage = error.response.data.error;
      }

      Alert.alert('Registration Error', errorMessage);
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async (): Promise<void> => {
    try {
      setIsLoading(true);

      const token = await SecureStore.getItemAsync('auth_token');
      if (token) {
        // Notify server about logout
        try {
          await axios.post(`${baseURL}/api/auth/logout`, {}, {
            headers: { Authorization: `Bearer ${token}` },
          });
        } catch (error) {
          // Ignore logout API errors
          console.warn('Logout API call failed:', error);
        }
      }

      // Clear stored tokens and user data
      await SecureStore.deleteItemAsync('auth_token');
      await SecureStore.deleteItemAsync('refresh_token');
      await SecureStore.deleteItemAsync('user_preferences');

      setUser(null);
      setIsAuthenticated(false);
    } catch (error) {
      console.error('Logout failed:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const refreshToken = async (): Promise<boolean> => {
    try {
      const refreshTokenValue = await SecureStore.getItemAsync('refresh_token');
      if (!refreshTokenValue) {
        return false;
      }

      const response: AxiosResponse<{
        access_token: string;
        refresh_token: string;
        user: User;
      }> = await axios.post(`${baseURL}/api/auth/refresh`, {
        refresh_token: refreshTokenValue,
      });

      const { access_token, refresh_token: newRefreshToken, user: userData } = response.data;

      // Update stored tokens
      await SecureStore.setItemAsync('auth_token', access_token);
      await SecureStore.setItemAsync('refresh_token', newRefreshToken);

      setUser(userData);
      setIsAuthenticated(true);

      return true;
    } catch (error) {
      console.error('Token refresh failed:', error);
      
      // Clear invalid tokens
      await SecureStore.deleteItemAsync('auth_token');
      await SecureStore.deleteItemAsync('refresh_token');
      
      setUser(null);
      setIsAuthenticated(false);
      
      return false;
    }
  };

  const updateProfile = async (updates: Partial<User>): Promise<boolean> => {
    try {
      const token = await SecureStore.getItemAsync('auth_token');
      if (!token) {
        return false;
      }

      const response: AxiosResponse<{ user: User }> = await axios.put(
        `${baseURL}/api/user/profile`,
        updates,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      setUser(response.data.user);
      return true;
    } catch (error) {
      console.error('Profile update failed:', error);
      
      let errorMessage = 'Failed to update profile. Please try again.';
      if (error.response?.data?.error) {
        errorMessage = error.response.data.error;
      }

      Alert.alert('Update Error', errorMessage);
      return false;
    }
  };

  // Auto-refresh token when it's about to expire
  useEffect(() => {
    if (!isAuthenticated) return;

    const checkTokenExpiry = async () => {
      try {
        const token = await SecureStore.getItemAsync('auth_token');
        if (!token) return;

        // Decode JWT to check expiry (simplified)
        const payload = JSON.parse(atob(token.split('.')[1]));
        const currentTime = Date.now() / 1000;
        
        // Refresh if token expires in less than 5 minutes
        if (payload.exp - currentTime < 300) {
          await refreshToken();
        }
      } catch (error) {
        console.error('Token expiry check failed:', error);
      }
    };

    // Check token expiry every minute
    const interval = setInterval(checkTokenExpiry, 60000);
    
    return () => clearInterval(interval);
  }, [isAuthenticated]);

  const contextValue: AuthContextType = {
    user,
    isAuthenticated,
    isLoading,
    login,
    logout,
    register,
    refreshToken,
    updateProfile,
  };

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
};
