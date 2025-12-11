import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { FixedSizeList as List } from 'react-window';
import { FixedSizeList } from 'react-window';
import AutoSizer from 'react-virtualized-auto-sizer';
import InfiniteLoader from 'react-window-infinite-loader';
import { debounce } from 'lodash';

/**
 * High-performance virtual scrolling component
 * Optimized for large datasets with minimal memory footprint
 */
const VirtualScrollList = ({
  items = [],
  itemHeight = 50,
  renderItem,
  loadMoreItems,
  hasNextPage = false,
  isNextPageLoading = false,
  threshold = 15,
  className = '',
  onScroll,
  overscanCount = 5,
  useIsScrolling = false,
  ...props
}) => {
  const listRef = useRef(null);
  const [scrollOffset, setScrollOffset] = useState(0);
  const [isScrolling, setIsScrolling] = useState(false);

  // Memoized item count for infinite loading
  const itemCount = useMemo(() => {
    return hasNextPage ? items.length + 1 : items.length;
  }, [items.length, hasNextPage]);

  // Check if item is loaded
  const isItemLoaded = useCallback((index) => {
    return !!items[index];
  }, [items]);

  // Debounced scroll handler to improve performance
  const debouncedScrollHandler = useMemo(
    () => debounce((scrollTop) => {
      setScrollOffset(scrollTop);
      if (onScroll) {
        onScroll(scrollTop);
      }
    }, 16), // 60fps
    [onScroll]
  );

  // Handle scroll events
  const handleScroll = useCallback(({ scrollOffset, scrollUpdateWasRequested }) => {
    if (!scrollUpdateWasRequested) {
      debouncedScrollHandler(scrollOffset);
    }
  }, [debouncedScrollHandler]);

  // Handle scroll start/stop for performance optimization
  const handleScrollStart = useCallback(() => {
    setIsScrolling(true);
  }, []);

  const handleScrollStop = useCallback(() => {
    setIsScrolling(false);
  }, []);

  // Optimized item renderer with memoization
  const ItemRenderer = useCallback(({ index, style, isScrolling: itemIsScrolling }) => {
    const item = items[index];
    
    // Show loading placeholder for unloaded items
    if (!item) {
      return (
        <div style={style} className="flex items-center justify-center p-4">
          <div className="animate-pulse flex space-x-4 w-full">
            <div className="rounded-full bg-gray-300 h-10 w-10"></div>
            <div className="flex-1 space-y-2 py-1">
              <div className="h-4 bg-gray-300 rounded w-3/4"></div>
              <div className="h-4 bg-gray-300 rounded w-1/2"></div>
            </div>
          </div>
        </div>
      );
    }

    // Render actual item
    return (
      <div style={style}>
        {renderItem({ 
          item, 
          index, 
          isScrolling: useIsScrolling ? itemIsScrolling : false 
        })}
      </div>
    );
  }, [items, renderItem, useIsScrolling]);

  // Memoize the ItemRenderer to prevent unnecessary re-renders
  const MemoizedItemRenderer = useMemo(() => 
    React.memo(ItemRenderer), 
    [ItemRenderer]
  );

  // Scroll to specific item
  const scrollToItem = useCallback((index, align = 'auto') => {
    if (listRef.current) {
      listRef.current.scrollToItem(index, align);
    }
  }, []);

  // Scroll to top
  const scrollToTop = useCallback(() => {
    if (listRef.current) {
      listRef.current.scrollTo(0);
    }
  }, []);

  // Get visible range
  const getVisibleRange = useCallback(() => {
    if (listRef.current) {
      const { visibleStartIndex, visibleStopIndex } = listRef.current.state;
      return { start: visibleStartIndex, end: visibleStopIndex };
    }
    return { start: 0, end: 0 };
  }, []);

  // Expose methods via ref
  useEffect(() => {
    if (props.ref) {
      props.ref.current = {
        scrollToItem,
        scrollToTop,
        getVisibleRange,
        scrollOffset
      };
    }
  }, [scrollToItem, scrollToTop, getVisibleRange, scrollOffset, props.ref]);

  // Cleanup debounced function on unmount
  useEffect(() => {
    return () => {
      debouncedScrollHandler.cancel();
    };
  }, [debouncedScrollHandler]);

  return (
    <div className={`virtual-scroll-container ${className}`} style={{ height: '100%' }}>
      <AutoSizer>
        {({ height, width }) => (
          <InfiniteLoader
            isItemLoaded={isItemLoaded}
            itemCount={itemCount}
            loadMoreItems={loadMoreItems}
            threshold={threshold}
          >
            {({ onItemsRendered, ref }) => (
              <List
                ref={(list) => {
                  listRef.current = list;
                  ref(list);
                }}
                height={height}
                width={width}
                itemCount={itemCount}
                itemSize={itemHeight}
                onItemsRendered={onItemsRendered}
                onScroll={handleScroll}
                onScrollStart={handleScrollStart}
                onScrollStop={handleScrollStop}
                overscanCount={overscanCount}
                useIsScrolling={useIsScrolling}
                {...props}
              >
                {MemoizedItemRenderer}
              </List>
            )}
          </InfiniteLoader>
        )}
      </AutoSizer>
    </div>
  );
};

export default React.memo(VirtualScrollList);

// Hook for managing virtual scroll state
export const useVirtualScroll = (items, itemHeight = 50) => {
  const [visibleRange, setVisibleRange] = useState({ start: 0, end: 0 });
  const [scrollOffset, setScrollOffset] = useState(0);
  const listRef = useRef(null);

  const scrollToItem = useCallback((index, align = 'auto') => {
    if (listRef.current) {
      listRef.current.scrollToItem(index, align);
    }
  }, []);

  const scrollToTop = useCallback(() => {
    if (listRef.current) {
      listRef.current.scrollToTop();
    }
  }, []);

  const getItemOffset = useCallback((index) => {
    return index * itemHeight;
  }, [itemHeight]);

  const getVisibleItems = useCallback(() => {
    return items.slice(visibleRange.start, visibleRange.end + 1);
  }, [items, visibleRange]);

  return {
    listRef,
    visibleRange,
    scrollOffset,
    scrollToItem,
    scrollToTop,
    getItemOffset,
    getVisibleItems,
    setVisibleRange,
    setScrollOffset
  };
};

// Performance monitoring hook for virtual scroll
export const useVirtualScrollPerformance = () => {
  const [metrics, setMetrics] = useState({
    renderTime: 0,
    scrollFPS: 0,
    memoryUsage: 0,
    visibleItems: 0
  });

  const measureRenderTime = useCallback((callback) => {
    const start = performance.now();
    callback();
    const end = performance.now();
    
    setMetrics(prev => ({
      ...prev,
      renderTime: end - start
    }));
  }, []);

  const trackScrollFPS = useCallback(() => {
    let frameCount = 0;
    let lastTime = performance.now();

    const countFrames = () => {
      frameCount++;
      const currentTime = performance.now();
      
      if (currentTime - lastTime >= 1000) {
        setMetrics(prev => ({
          ...prev,
          scrollFPS: frameCount
        }));
        frameCount = 0;
        lastTime = currentTime;
      }
      
      requestAnimationFrame(countFrames);
    };

    requestAnimationFrame(countFrames);
  }, []);

  useEffect(() => {
    trackScrollFPS();
  }, [trackScrollFPS]);

  return {
    metrics,
    measureRenderTime
  };
};
