/**
 * Immersive 3D Security Heatmap with WebGL Rendering
 * Advanced threat visualization with spatial depth and interactive exploration
 */

import React, { useRef, useEffect, useState, useMemo } from 'react';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import { OrbitControls, Text, Html, useTexture } from '@react-three/drei';
import { motion } from 'framer-motion-3d';
import * as THREE from 'three';
import { useSpring, animated } from '@react-spring/three';

// Quantum-Ready 3D Security Visualization Component
const SecurityHeatmap3D = ({ 
  vulnerabilityData, 
  networkTopology, 
  threatLevel = 'medium',
  interactionMode = 'explore' // 'explore', 'analyze', 'respond'
}) => {
  const [selectedNode, setSelectedNode] = useState(null);
  const [hoverNode, setHoverNode] = useState(null);
  const [viewMode, setViewMode] = useState('network'); // 'network', 'code', 'threats'
  
  // Adaptive color scheme based on threat level
  const threatColors = useMemo(() => ({
    critical: '#ff0040',
    high: '#ff6b35',
    medium: '#f7931e',
    low: '#4ecdc4',
    info: '#45b7d1'
  }), []);

  return (
    <div className="relative w-full h-full bg-black/90 rounded-2xl overflow-hidden">
      {/* 3D Canvas with Advanced Lighting */}
      <Canvas
        camera={{ position: [0, 0, 10], fov: 60 }}
        gl={{ 
          antialias: true, 
          alpha: true,
          powerPreference: "high-performance"
        }}
        className="w-full h-full"
      >
        {/* Advanced Lighting Setup */}
        <ambientLight intensity={0.2} />
        <pointLight position={[10, 10, 10]} intensity={0.8} color="#4ecdc4" />
        <spotLight 
          position={[-10, -10, -10]} 
          angle={0.3} 
          penumbra={1} 
          intensity={0.5}
          color="#ff6b35"
        />
        
        {/* Interactive 3D Security Nodes */}
        <SecurityNodes 
          data={vulnerabilityData}
          onNodeSelect={setSelectedNode}
          onNodeHover={setHoverNode}
          threatColors={threatColors}
          viewMode={viewMode}
        />
        
        {/* 3D Threat Connections */}
        <ThreatConnections 
          topology={networkTopology}
          selectedNode={selectedNode}
          threatColors={threatColors}
        />
        
        {/* Spatial Information Overlays */}
        <SpatialInfoOverlays 
          selectedNode={selectedNode}
          hoverNode={hoverNode}
        />
        
        {/* Interactive Controls */}
        <OrbitControls 
          enablePan={true}
          enableZoom={true}
          enableRotate={true}
          maxDistance={50}
          minDistance={2}
        />
      </Canvas>
      
      {/* Holographic UI Controls */}
      <HolographicControls 
        viewMode={viewMode}
        onViewModeChange={setViewMode}
        threatLevel={threatLevel}
        selectedNode={selectedNode}
      />
      
      {/* Contextual Information Panel */}
      <ContextualInfoPanel 
        selectedNode={selectedNode}
        vulnerabilityData={vulnerabilityData}
      />
    </div>
  );
};

// 3D Security Nodes with Interactive Animations
const SecurityNodes = ({ data, onNodeSelect, onNodeHover, threatColors, viewMode }) => {
  const groupRef = useRef();
  
  useFrame((state) => {
    if (groupRef.current) {
      groupRef.current.rotation.y += 0.001;
    }
  });

  return (
    <group ref={groupRef}>
      {data.map((node, index) => (
        <SecurityNode
          key={node.id}
          node={node}
          position={[
            (index % 10 - 5) * 2,
            Math.floor(index / 10) * 2 - 5,
            Math.sin(index * 0.5) * 2
          ]}
          onSelect={onNodeSelect}
          onHover={onNodeHover}
          color={threatColors[node.severity]}
          viewMode={viewMode}
        />
      ))}
    </group>
  );
};

// Individual Security Node with Advanced Interactions
const SecurityNode = ({ node, position, onSelect, onHover, color, viewMode }) => {
  const meshRef = useRef();
  const [hovered, setHovered] = useState(false);
  const [selected, setSelected] = useState(false);
  
  // Animated properties
  const { scale, emissive } = useSpring({
    scale: hovered ? 1.5 : selected ? 1.3 : 1,
    emissive: hovered ? 0.3 : selected ? 0.2 : 0,
    config: { tension: 300, friction: 10 }
  });

  useFrame((state) => {
    if (meshRef.current && (hovered || selected)) {
      meshRef.current.rotation.x += 0.02;
      meshRef.current.rotation.y += 0.02;
    }
  });

  const handleClick = () => {
    setSelected(!selected);
    onSelect(selected ? null : node);
  };

  const handlePointerOver = () => {
    setHovered(true);
    onHover(node);
    document.body.style.cursor = 'pointer';
  };

  const handlePointerOut = () => {
    setHovered(false);
    onHover(null);
    document.body.style.cursor = 'auto';
  };

  return (
    <animated.mesh
      ref={meshRef}
      position={position}
      scale={scale}
      onClick={handleClick}
      onPointerOver={handlePointerOver}
      onPointerOut={handlePointerOut}
    >
      {/* Dynamic geometry based on threat type */}
      {node.type === 'critical' ? (
        <octahedronGeometry args={[0.5, 0]} />
      ) : node.type === 'network' ? (
        <sphereGeometry args={[0.4, 16, 16]} />
      ) : (
        <boxGeometry args={[0.6, 0.6, 0.6]} />
      )}
      
      <animated.meshStandardMaterial
        color={color}
        emissive={color}
        emissiveIntensity={emissive}
        transparent
        opacity={0.8}
        roughness={0.2}
        metalness={0.8}
      />
      
      {/* Floating vulnerability count */}
      <Html distanceFactor={10}>
        <div className="bg-black/80 text-white px-2 py-1 rounded text-xs font-mono">
          {node.vulnerabilityCount}
        </div>
      </Html>
    </animated.mesh>
  );
};

// 3D Threat Connection Lines
const ThreatConnections = ({ topology, selectedNode, threatColors }) => {
  const connectionsRef = useRef();
  
  useFrame((state) => {
    if (connectionsRef.current) {
      connectionsRef.current.children.forEach((line, index) => {
        line.material.opacity = 0.3 + Math.sin(state.clock.elapsedTime + index) * 0.2;
      });
    }
  });

  return (
    <group ref={connectionsRef}>
      {topology.connections.map((connection, index) => (
        <ThreatConnection
          key={`${connection.from}-${connection.to}`}
          from={connection.fromPosition}
          to={connection.toPosition}
          severity={connection.severity}
          color={threatColors[connection.severity]}
          active={selectedNode?.id === connection.from || selectedNode?.id === connection.to}
        />
      ))}
    </group>
  );
};

// Individual Threat Connection Line
const ThreatConnection = ({ from, to, severity, color, active }) => {
  const lineRef = useRef();
  
  const points = useMemo(() => [
    new THREE.Vector3(...from),
    new THREE.Vector3(...to)
  ], [from, to]);

  const geometry = useMemo(() => {
    const geometry = new THREE.BufferGeometry().setFromPoints(points);
    return geometry;
  }, [points]);

  return (
    <line ref={lineRef} geometry={geometry}>
      <lineBasicMaterial 
        color={color} 
        transparent 
        opacity={active ? 0.8 : 0.3}
        linewidth={active ? 3 : 1}
      />
    </line>
  );
};

// Spatial Information Overlays
const SpatialInfoOverlays = ({ selectedNode, hoverNode }) => {
  const displayNode = selectedNode || hoverNode;
  
  if (!displayNode) return null;

  return (
    <Html
      position={[displayNode.position?.[0] || 0, displayNode.position?.[1] + 2 || 2, displayNode.position?.[2] || 0]}
      center
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.8 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.8 }}
        className="bg-black/90 backdrop-blur-xl border border-cyan-500/30 rounded-xl p-4 min-w-64"
      >
        <h3 className="text-cyan-400 font-semibold mb-2">{displayNode.name}</h3>
        <div className="space-y-1 text-sm text-gray-300">
          <div>Type: <span className="text-white">{displayNode.type}</span></div>
          <div>Severity: <span className={`text-${displayNode.severity === 'critical' ? 'red' : displayNode.severity === 'high' ? 'orange' : 'yellow'}-400`}>
            {displayNode.severity}
          </span></div>
          <div>Vulnerabilities: <span className="text-white">{displayNode.vulnerabilityCount}</span></div>
          <div>Risk Score: <span className="text-white">{displayNode.riskScore}/100</span></div>
        </div>
      </motion.div>
    </Html>
  );
};

// Holographic UI Controls
const HolographicControls = ({ viewMode, onViewModeChange, threatLevel, selectedNode }) => {
  return (
    <div className="absolute top-4 left-4 z-10">
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="glass-panel p-4 space-y-3"
      >
        {/* View Mode Selector */}
        <div className="space-y-2">
          <label className="text-xs text-gray-400 uppercase tracking-wide">View Mode</label>
          <div className="flex space-x-2">
            {['network', 'code', 'threats'].map((mode) => (
              <button
                key={mode}
                onClick={() => onViewModeChange(mode)}
                className={`px-3 py-1 rounded-lg text-xs font-medium transition-all ${
                  viewMode === mode
                    ? 'bg-cyan-500 text-white'
                    : 'bg-white/10 text-gray-300 hover:bg-white/20'
                }`}
              >
                {mode.charAt(0).toUpperCase() + mode.slice(1)}
              </button>
            ))}
          </div>
        </div>
        
        {/* Threat Level Indicator */}
        <div className="space-y-2">
          <label className="text-xs text-gray-400 uppercase tracking-wide">Threat Level</label>
          <div className={`px-3 py-2 rounded-lg text-sm font-medium ${
            threatLevel === 'critical' ? 'bg-red-500/20 text-red-400' :
            threatLevel === 'high' ? 'bg-orange-500/20 text-orange-400' :
            threatLevel === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
            'bg-green-500/20 text-green-400'
          }`}>
            {threatLevel.toUpperCase()}
          </div>
        </div>
      </motion.div>
    </div>
  );
};

// Contextual Information Panel
const ContextualInfoPanel = ({ selectedNode, vulnerabilityData }) => {
  if (!selectedNode) return null;

  return (
    <motion.div
      initial={{ opacity: 0, x: 300 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 300 }}
      className="absolute top-4 right-4 bottom-4 w-80 glass-panel p-6 overflow-y-auto z-10"
    >
      <div className="space-y-6">
        <div>
          <h2 className="text-xl font-bold text-white mb-2">{selectedNode.name}</h2>
          <p className="text-gray-400 text-sm">{selectedNode.description}</p>
        </div>
        
        {/* Vulnerability Details */}
        <div>
          <h3 className="text-lg font-semibold text-cyan-400 mb-3">Vulnerabilities</h3>
          <div className="space-y-3">
            {selectedNode.vulnerabilities?.map((vuln, index) => (
              <div key={index} className="bg-black/40 rounded-lg p-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium text-white">{vuln.title}</span>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${
                    vuln.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                    vuln.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                    vuln.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                    'bg-green-500/20 text-green-400'
                  }`}>
                    {vuln.severity}
                  </span>
                </div>
                <p className="text-gray-400 text-sm">{vuln.description}</p>
              </div>
            ))}
          </div>
        </div>
        
        {/* Remediation Actions */}
        <div>
          <h3 className="text-lg font-semibold text-cyan-400 mb-3">Recommended Actions</h3>
          <div className="space-y-2">
            {selectedNode.recommendations?.map((rec, index) => (
              <button
                key={index}
                className="w-full text-left p-3 bg-cyan-500/10 hover:bg-cyan-500/20 rounded-lg transition-colors"
              >
                <div className="font-medium text-white">{rec.action}</div>
                <div className="text-sm text-gray-400">{rec.description}</div>
              </button>
            ))}
          </div>
        </div>
      </div>
    </motion.div>
  );
};

export default SecurityHeatmap3D;
