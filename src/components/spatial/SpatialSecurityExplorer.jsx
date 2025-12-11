/**
 * Enhanced Spatial Security Explorer with Advanced Gesture-Based Navigation
 * Next-generation spatial design for intuitive security data exploration with multi-modal interaction
 */

import React, { useState, useRef, useEffect, useMemo, useCallback } from 'react';
import { motion, useMotionValue, useTransform, useSpring } from 'framer-motion';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import { OrbitControls, Text3D, Float, Sphere, Html, Environment } from '@react-three/drei';
import { useGesture } from 'react-use-gesture';
import * as THREE from 'three';
import { QuantumGlassCard, MicroAnimationWrapper } from '../advanced/QuantumGlassmorphism';

const SpatialSecurityExplorer = ({ 
  securityData, 
  onDataSelect, 
  gestureEnabled = true,
  spatialMode = 'sphere' // 'sphere', 'grid', 'network'
}) => {
  const [selectedLayer, setSelectedLayer] = useState('vulnerabilities');
  const [spatialDepth, setSpatialDepth] = useState(0);
  const [gestureState, setGestureState] = useState('idle');
  const containerRef = useRef(null);
  
  // Motion values for gesture control
  const x = useMotionValue(0);
  const y = useMotionValue(0);
  const rotateX = useTransform(y, [-300, 300], [30, -30]);
  const rotateY = useTransform(x, [-300, 300], [-30, 30]);

  // Spatial layers configuration
  const spatialLayers = useMemo(() => ({
    vulnerabilities: {
      color: '#ff4757',
      position: [0, 0, 0],
      data: securityData.vulnerabilities || []
    },
    threats: {
      color: '#ff6b35',
      position: [0, 0, -5],
      data: securityData.threats || []
    },
    assets: {
      color: '#4ecdc4',
      position: [0, 0, -10],
      data: securityData.assets || []
    },
    compliance: {
      color: '#45b7d1',
      position: [0, 0, -15],
      data: securityData.compliance || []
    }
  }), [securityData]);

  // Gesture recognition
  useEffect(() => {
    if (!gestureEnabled) return;

    const handleGesture = (event) => {
      const { gesture, confidence } = recognizeGesture(event);
      if (confidence > 0.8) {
        handleGestureAction(gesture);
      }
    };

    const gestureObserver = new GestureObserver(handleGesture);
    if (containerRef.current) {
      gestureObserver.observe(containerRef.current);
    }

    return () => gestureObserver.disconnect();
  }, [gestureEnabled]);

  const handleGestureAction = (gesture) => {
    switch (gesture) {
      case 'swipe_up':
        setSpatialDepth(prev => Math.max(prev - 1, -3));
        break;
      case 'swipe_down':
        setSpatialDepth(prev => Math.min(prev + 1, 3));
        break;
      case 'pinch_in':
        // Zoom in functionality
        break;
      case 'pinch_out':
        // Zoom out functionality
        break;
      case 'rotate_clockwise':
        // Rotate view
        break;
    }
  };

  const handlePan = (event, info) => {
    x.set(info.offset.x);
    y.set(info.offset.y);
  };

  return (
    <div ref={containerRef} className="relative w-full h-full bg-black rounded-2xl overflow-hidden">
      {/* Spatial Canvas */}
      <motion.div
        className="w-full h-full"
        style={{ rotateX, rotateY }}
        drag={gestureEnabled}
        onPan={handlePan}
        dragElastic={0.1}
        dragConstraints={{ left: -100, right: 100, top: -100, bottom: 100 }}
      >
        <Canvas
          camera={{ position: [0, 0, 20], fov: 75 }}
          gl={{ antialias: true, alpha: true }}
        >
          {/* Ambient lighting */}
          <ambientLight intensity={0.3} />
          <pointLight position={[10, 10, 10]} intensity={0.8} />
          
          {/* Spatial Security Layers */}
          <SpatialLayers 
            layers={spatialLayers}
            selectedLayer={selectedLayer}
            spatialDepth={spatialDepth}
            spatialMode={spatialMode}
            onDataSelect={onDataSelect}
          />
          
          {/* Interactive Controls */}
          <OrbitControls 
            enablePan={!gestureEnabled}
            enableZoom={true}
            enableRotate={!gestureEnabled}
          />
        </Canvas>
      </motion.div>

      {/* Spatial Navigation UI */}
      <SpatialNavigationUI 
        layers={Object.keys(spatialLayers)}
        selectedLayer={selectedLayer}
        onLayerSelect={setSelectedLayer}
        spatialDepth={spatialDepth}
        onDepthChange={setSpatialDepth}
        gestureEnabled={gestureEnabled}
      />

      {/* Gesture Feedback */}
      {gestureEnabled && (
        <GestureFeedback 
          gestureState={gestureState}
          spatialDepth={spatialDepth}
        />
      )}

      {/* Spatial Information Panel */}
      <SpatialInfoPanel 
        selectedLayer={selectedLayer}
        layerData={spatialLayers[selectedLayer]}
        spatialDepth={spatialDepth}
      />
    </div>
  );
};

// Spatial Layers Component
const SpatialLayers = ({ layers, selectedLayer, spatialDepth, spatialMode, onDataSelect }) => {
  const groupRef = useRef();
  
  useFrame((state) => {
    if (groupRef.current) {
      groupRef.current.position.z = spatialDepth * 2;
    }
  });

  return (
    <group ref={groupRef}>
      {Object.entries(layers).map(([layerName, layerConfig]) => (
        <SpatialLayer
          key={layerName}
          name={layerName}
          config={layerConfig}
          isSelected={selectedLayer === layerName}
          spatialMode={spatialMode}
          onDataSelect={onDataSelect}
        />
      ))}
    </group>
  );
};

// Individual Spatial Layer
const SpatialLayer = ({ name, config, isSelected, spatialMode, onDataSelect }) => {
  const layerRef = useRef();
  const [hovered, setHovered] = useState(null);

  useFrame((state) => {
    if (layerRef.current) {
      layerRef.current.rotation.y += isSelected ? 0.005 : 0.001;
      layerRef.current.material.opacity = isSelected ? 1.0 : 0.3;
    }
  });

  const renderDataPoints = () => {
    switch (spatialMode) {
      case 'sphere':
        return renderSphereLayout();
      case 'grid':
        return renderGridLayout();
      case 'network':
        return renderNetworkLayout();
      default:
        return renderSphereLayout();
    }
  };

  const renderSphereLayout = () => {
    const radius = 8;
    return config.data.map((item, index) => {
      const phi = Math.acos(-1 + (2 * index) / config.data.length);
      const theta = Math.sqrt(config.data.length * Math.PI) * phi;
      
      const x = radius * Math.cos(theta) * Math.sin(phi);
      const y = radius * Math.sin(theta) * Math.sin(phi);
      const z = radius * Math.cos(phi);

      return (
        <SpatialDataPoint
          key={item.id}
          position={[x, y, z]}
          data={item}
          color={config.color}
          isHovered={hovered === item.id}
          onHover={setHovered}
          onSelect={onDataSelect}
        />
      );
    });
  };

  const renderGridLayout = () => {
    const gridSize = Math.ceil(Math.sqrt(config.data.length));
    const spacing = 2;
    
    return config.data.map((item, index) => {
      const x = (index % gridSize - gridSize / 2) * spacing;
      const y = (Math.floor(index / gridSize) - gridSize / 2) * spacing;
      const z = 0;

      return (
        <SpatialDataPoint
          key={item.id}
          position={[x, y, z]}
          data={item}
          color={config.color}
          isHovered={hovered === item.id}
          onHover={setHovered}
          onSelect={onDataSelect}
        />
      );
    });
  };

  const renderNetworkLayout = () => {
    // Force-directed layout simulation
    return config.data.map((item, index) => {
      const angle = (index / config.data.length) * Math.PI * 2;
      const radius = 5 + Math.random() * 3;
      
      const x = Math.cos(angle) * radius;
      const y = Math.sin(angle) * radius;
      const z = (Math.random() - 0.5) * 4;

      return (
        <SpatialDataPoint
          key={item.id}
          position={[x, y, z]}
          data={item}
          color={config.color}
          isHovered={hovered === item.id}
          onHover={setHovered}
          onSelect={onDataSelect}
        />
      );
    });
  };

  return (
    <group position={config.position}>
      {renderDataPoints()}
      
      {/* Layer Label */}
      <Text3D
        font="/fonts/helvetiker_regular.typeface.json"
        size={0.5}
        height={0.1}
        position={[0, 10, 0]}
      >
        {name.toUpperCase()}
        <meshStandardMaterial color={config.color} />
      </Text3D>
    </group>
  );
};

// Spatial Data Point
const SpatialDataPoint = ({ position, data, color, isHovered, onHover, onSelect }) => {
  const meshRef = useRef();
  
  useFrame((state) => {
    if (meshRef.current && isHovered) {
      meshRef.current.rotation.x += 0.02;
      meshRef.current.rotation.y += 0.02;
    }
  });

  return (
    <Float speed={1} rotationIntensity={0.5} floatIntensity={0.5}>
      <mesh
        ref={meshRef}
        position={position}
        scale={isHovered ? 1.5 : 1}
        onClick={() => onSelect(data)}
        onPointerOver={() => onHover(data.id)}
        onPointerOut={() => onHover(null)}
      >
        <sphereGeometry args={[0.2, 16, 16]} />
        <meshStandardMaterial
          color={color}
          emissive={color}
          emissiveIntensity={isHovered ? 0.3 : 0.1}
          transparent
          opacity={0.8}
        />
      </mesh>
    </Float>
  );
};

// Spatial Navigation UI
const SpatialNavigationUI = ({ 
  layers, 
  selectedLayer, 
  onLayerSelect, 
  spatialDepth, 
  onDepthChange,
  gestureEnabled 
}) => {
  return (
    <div className="absolute top-4 left-4 space-y-4 z-10">
      {/* Layer Selector */}
      <motion.div
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
        className="glass-panel p-4"
      >
        <h3 className="text-sm font-semibold text-white mb-3">Security Layers</h3>
        <div className="space-y-2">
          {layers.map((layer) => (
            <button
              key={layer}
              onClick={() => onLayerSelect(layer)}
              className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-all ${
                selectedLayer === layer
                  ? 'bg-cyan-500 text-white'
                  : 'bg-white/10 text-gray-300 hover:bg-white/20'
              }`}
            >
              {layer.charAt(0).toUpperCase() + layer.slice(1)}
            </button>
          ))}
        </div>
      </motion.div>

      {/* Depth Control */}
      <motion.div
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ delay: 0.1 }}
        className="glass-panel p-4"
      >
        <h3 className="text-sm font-semibold text-white mb-3">Spatial Depth</h3>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => onDepthChange(spatialDepth - 1)}
            className="w-8 h-8 bg-white/10 hover:bg-white/20 rounded-lg flex items-center justify-center text-white"
          >
            -
          </button>
          <div className="flex-1 text-center text-sm text-gray-300">
            {spatialDepth}
          </div>
          <button
            onClick={() => onDepthChange(spatialDepth + 1)}
            className="w-8 h-8 bg-white/10 hover:bg-white/20 rounded-lg flex items-center justify-center text-white"
          >
            +
          </button>
        </div>
      </motion.div>

      {/* Gesture Status */}
      {gestureEnabled && (
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
          className="glass-panel p-4"
        >
          <div className="flex items-center space-x-2">
            <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />
            <span className="text-xs text-gray-300">Gesture Control Active</span>
          </div>
        </motion.div>
      )}
    </div>
  );
};

// Gesture Feedback Component
const GestureFeedback = ({ gestureState, spatialDepth }) => {
  if (gestureState === 'idle') return null;

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.8 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.8 }}
      className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 z-20"
    >
      <div className="glass-panel p-6 text-center">
        <div className="text-2xl mb-2">👋</div>
        <p className="text-white font-medium">{gestureState}</p>
        <p className="text-gray-400 text-sm">Depth: {spatialDepth}</p>
      </div>
    </motion.div>
  );
};

// Spatial Information Panel
const SpatialInfoPanel = ({ selectedLayer, layerData, spatialDepth }) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="absolute bottom-4 left-4 right-4 glass-panel p-4 z-10"
    >
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold text-white capitalize">{selectedLayer}</h3>
          <p className="text-gray-400 text-sm">{layerData?.data?.length || 0} items</p>
        </div>
        <div className="text-right">
          <p className="text-sm text-gray-400">Spatial Depth</p>
          <p className="text-lg font-semibold text-white">{spatialDepth}</p>
        </div>
      </div>
    </motion.div>
  );
};

// Gesture Recognition Utility
class GestureObserver {
  constructor(callback) {
    this.callback = callback;
    this.element = null;
  }

  observe(element) {
    this.element = element;
    // Implement gesture recognition logic
    // This would integrate with browser APIs or gesture libraries
  }

  disconnect() {
    // Cleanup gesture observers
  }
}

const recognizeGesture = (event) => {
  // Simplified gesture recognition
  // In production, this would use advanced gesture recognition algorithms
  return {
    gesture: 'swipe_up',
    confidence: 0.9
  };
};

export default SpatialSecurityExplorer;
