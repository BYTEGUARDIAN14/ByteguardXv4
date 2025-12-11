import { useQuery, useMutation, useQueryClient, useInfiniteQuery } from '@tanstack/react-query';
import { useCallback, useMemo, useRef, useEffect } from 'react';
import { useAppStore } from '../store';

/**
 * Advanced React Query hooks with optimistic updates, caching, and performance optimization
 */

// Query client configuration
export const queryClientConfig = {
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000, // 5 minutes
      cacheTime: 10 * 60 * 1000, // 10 minutes
      retry: (failureCount, error) => {
        if (error.status === 404 || error.status === 403) return false;
        return failureCount < 3;
      },
      retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 30000),
      refetchOnWindowFocus: false,
      refetchOnReconnect: true
    },
    mutations: {
      retry: 1,
      retryDelay: 1000
    }
  }
};

// Advanced query hook with performance monitoring
export const useAdvancedQuery = (key, queryFn, options = {}) => {
  const queryClient = useQueryClient();
  const addNotification = useAppStore(state => state.addNotification);
  const startTime = useRef(null);

  const enhancedOptions = useMemo(() => ({
    ...options,
    onSuccess: (data) => {
      const loadTime = performance.now() - startTime.current;
      if (loadTime > 2000) {
        console.warn(`Slow query: ${key} took ${loadTime}ms`);
      }
      options.onSuccess?.(data);
    },
    onError: (error) => {
      addNotification({
        type: 'error',
        title: 'Query Error',
        message: error.message || 'Failed to fetch data',
        duration: 5000
      });
      options.onError?.(error);
    }
  }), [key, options, addNotification]);

  const query = useQuery(key, queryFn, enhancedOptions);

  useEffect(() => {
    if (query.isFetching) {
      startTime.current = performance.now();
    }
  }, [query.isFetching]);

  return query;
};

// Optimistic mutation hook
export const useOptimisticMutation = (mutationFn, options = {}) => {
  const queryClient = useQueryClient();
  const addNotification = useAppStore(state => state.addNotification);

  return useMutation(mutationFn, {
    ...options,
    onMutate: async (variables) => {
      // Cancel outgoing refetches
      if (options.queryKey) {
        await queryClient.cancelQueries(options.queryKey);
      }

      // Snapshot previous value
      const previousData = options.queryKey ? 
        queryClient.getQueryData(options.queryKey) : null;

      // Optimistically update
      if (options.optimisticUpdate && options.queryKey) {
        queryClient.setQueryData(options.queryKey, (old) => 
          options.optimisticUpdate(old, variables)
        );
      }

      // Call custom onMutate
      const context = await options.onMutate?.(variables);

      return { previousData, ...context };
    },
    onError: (error, variables, context) => {
      // Rollback optimistic update
      if (context?.previousData && options.queryKey) {
        queryClient.setQueryData(options.queryKey, context.previousData);
      }

      addNotification({
        type: 'error',
        title: 'Operation Failed',
        message: error.message || 'Something went wrong',
        duration: 5000
      });

      options.onError?.(error, variables, context);
    },
    onSuccess: (data, variables, context) => {
      addNotification({
        type: 'success',
        title: 'Success',
        message: options.successMessage || 'Operation completed successfully',
        duration: 3000
      });

      options.onSuccess?.(data, variables, context);
    },
    onSettled: (data, error, variables, context) => {
      // Always refetch after mutation
      if (options.queryKey) {
        queryClient.invalidateQueries(options.queryKey);
      }

      options.onSettled?.(data, error, variables, context);
    }
  });
};

// Infinite query with virtual scrolling support
export const useInfiniteScroll = (queryKey, queryFn, options = {}) => {
  const {
    getNextPageParam = (lastPage, pages) => lastPage.nextCursor,
    ...restOptions
  } = options;

  const query = useInfiniteQuery(
    queryKey,
    queryFn,
    {
      getNextPageParam,
      ...restOptions
    }
  );

  const flatData = useMemo(() => 
    query.data?.pages.flatMap(page => page.data) || [],
    [query.data]
  );

  const loadMore = useCallback(() => {
    if (query.hasNextPage && !query.isFetchingNextPage) {
      query.fetchNextPage();
    }
  }, [query.hasNextPage, query.isFetchingNextPage, query.fetchNextPage]);

  return {
    ...query,
    data: flatData,
    loadMore,
    hasMore: query.hasNextPage,
    isLoadingMore: query.isFetchingNextPage
  };
};

// Real-time query with WebSocket integration
export const useRealTimeQuery = (queryKey, queryFn, wsUrl, options = {}) => {
  const queryClient = useQueryClient();
  const wsRef = useRef(null);

  const query = useAdvancedQuery(queryKey, queryFn, {
    ...options,
    refetchInterval: options.fallbackInterval || 30000 // Fallback polling
  });

  useEffect(() => {
    if (!wsUrl) return;

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      console.log('WebSocket connected for', queryKey);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        // Update query data with real-time updates
        queryClient.setQueryData(queryKey, (oldData) => {
          if (options.updateFn) {
            return options.updateFn(oldData, data);
          }
          return data;
        });
      } catch (error) {
        console.error('WebSocket message parsing error:', error);
      }
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };

    ws.onclose = () => {
      console.log('WebSocket disconnected for', queryKey);
      // Attempt reconnection after delay
      setTimeout(() => {
        if (wsRef.current?.readyState === WebSocket.CLOSED) {
          // Reconnect logic would go here
        }
      }, 5000);
    };

    return () => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.close();
      }
    };
  }, [wsUrl, queryKey, queryClient, options.updateFn]);

  return query;
};

// Prefetch hook for performance optimization
export const usePrefetch = () => {
  const queryClient = useQueryClient();

  const prefetchQuery = useCallback((queryKey, queryFn, options = {}) => {
    return queryClient.prefetchQuery(queryKey, queryFn, {
      staleTime: 5 * 60 * 1000,
      ...options
    });
  }, [queryClient]);

  const prefetchInfiniteQuery = useCallback((queryKey, queryFn, options = {}) => {
    return queryClient.prefetchInfiniteQuery(queryKey, queryFn, options);
  }, [queryClient]);

  return { prefetchQuery, prefetchInfiniteQuery };
};

// Background sync hook
export const useBackgroundSync = (queryKey, syncFn, interval = 60000) => {
  const queryClient = useQueryClient();
  const isOnline = useOnlineStatus();

  useEffect(() => {
    if (!isOnline) return;

    const sync = async () => {
      try {
        const result = await syncFn();
        if (result) {
          queryClient.setQueryData(queryKey, result);
        }
      } catch (error) {
        console.error('Background sync failed:', error);
      }
    };

    const intervalId = setInterval(sync, interval);
    
    // Initial sync
    sync();

    return () => clearInterval(intervalId);
  }, [queryKey, syncFn, interval, isOnline, queryClient]);
};

// Online status hook
export const useOnlineStatus = () => {
  const [isOnline, setIsOnline] = useState(navigator.onLine);

  useEffect(() => {
    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  return isOnline;
};

// Query performance monitoring
export const useQueryPerformance = () => {
  const queryClient = useQueryClient();

  const getQueryStats = useCallback(() => {
    const cache = queryClient.getQueryCache();
    const queries = cache.getAll();

    const stats = {
      totalQueries: queries.length,
      activeQueries: queries.filter(q => q.getObserversCount() > 0).length,
      staleQueries: queries.filter(q => q.isStale()).length,
      errorQueries: queries.filter(q => q.state.status === 'error').length,
      cacheSize: JSON.stringify(cache).length
    };

    return stats;
  }, [queryClient]);

  const clearStaleQueries = useCallback(() => {
    const cache = queryClient.getQueryCache();
    const staleQueries = cache.getAll().filter(q => q.isStale());
    
    staleQueries.forEach(query => {
      cache.remove(query);
    });

    return staleQueries.length;
  }, [queryClient]);

  return { getQueryStats, clearStaleQueries };
};

export default useAdvancedQuery;
