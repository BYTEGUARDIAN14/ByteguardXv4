/**
 * Immersive 3D Security Visualization
 * Interactive 3D network topology with threat overlays and spatial security heatmaps
 */

import React, { useState, useRef, useEffect, useMemo } from 'react';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import {
  OrbitControls,
  Text3D,
  Float,
  Sphere,
  Box,
  Cylinder,
  Html,
  Environment
} from '@react-three/drei';
import { motion } from 'framer-motion';
import * as THREE from 'three';
import { QuantumGlassCard } from '../advanced/QuantumGlassmorphism';

// 3D Network Node Component
const NetworkNode = ({ 
  position, 
  threatLevel = 'low', 
  nodeType = 'server', 
  vulnerabilities = [], 
  onClick,
  isSelected = false 
}) => {
  const meshRef = useRef();
  const [hovered, setHovered] = useState(false);

  const threatColors = {
    low: '#10B981',      // Green
    medium: '#F59E0B',   // Yellow
    high: '#EF4444',     // Red
    critical: '#8B5CF6'  // Purple
  };

  const nodeShapes = {
    server: Box,
    database: Cylinder,
    endpoint: Sphere,
    router: Box,
    firewall: Box
  };

  const NodeShape = nodeShapes[nodeType] || Box;

  useFrame((state) => {
    if (meshRef.current) {
      meshRef.current.rotation.y += 0.01;
      if (hovered || isSelected) {
        meshRef.current.scale.setScalar(1.2);
      } else {
        meshRef.current.scale.setScalar(1);
      }
    }
  });

  return (
    <Float speed={2} rotationIntensity={0.5} floatIntensity={0.5}>
      <group position={position}>
        <NodeShape
          ref={meshRef}
          args={nodeType === 'database' ? [0.5, 1, 0.5] : [1, 1, 1]}
          onPointerOver={() => setHovered(true)}
          onPointerOut={() => setHovered(false)}
          onClick={onClick}
        >
          <meshStandardMaterial
            color={threatColors[threatLevel]}
            emissive={threatColors[threatLevel]}
            emissiveIntensity={hovered ? 0.3 : 0.1}
            transparent
            opacity={0.8}
          />
        </NodeShape>

        {/* Vulnerability Indicators */}
        {vulnerabilities.length > 0 && (
          <Sphere position={[0, 1.5, 0]} args={[0.2]}>
            <meshStandardMaterial
              color="#EF4444"
              emissive="#EF4444"
              emissiveIntensity={0.5}
            />
          </Sphere>
        )}

        {/* Node Label */}
        <Html position={[0, -1.5, 0]} center>
          <div className="bg-black/80 text-white px-2 py-1 rounded text-xs whitespace-nowrap">
            {nodeType.toUpperCase()}
            {vulnerabilities.length > 0 && (
              <span className="ml-2 text-red-400">
                {vulnerabilities.length} vuln{vulnerabilities.length !== 1 ? 's' : ''}
              </span>
            )}
          </div>
        </Html>
      </group>
    </Float>
  );
};

// 3D Connection Lines
const NetworkConnection = ({ start, end, threatLevel = 'low', animated = true }) => {
  const lineRef = useRef();
  
  const threatColors = {
    low: 0x10B981,
    medium: 0xF59E0B,
    high: 0xEF4444,
    critical: 0x8B5CF6
  };

  const points = useMemo(() => {
    return [new THREE.Vector3(...start), new THREE.Vector3(...end)];
  }, [start, end]);

  const geometry = useMemo(() => {
    const geometry = new THREE.BufferGeometry().setFromPoints(points);
    return geometry;
  }, [points]);

  useFrame((state) => {
    if (lineRef.current && animated) {
      const time = state.clock.getElapsedTime();
      lineRef.current.material.opacity = 0.3 + Math.sin(time * 2) * 0.2;
    }
  });

  return (
    <line ref={lineRef} geometry={geometry}>
      <lineBasicMaterial 
        color={threatColors[threatLevel]} 
        transparent 
        opacity={0.5}
        linewidth={2}
      />
    </line>
  );
};

// Spatial Security Heatmap
const SecurityHeatmap = ({ data, dimensions = [10, 10, 10] }) => {
  const heatmapRef = useRef();
  
  const heatmapData = useMemo(() => {
    const points = [];
    const colors = [];
    
    for (let x = 0; x < dimensions[0]; x++) {
      for (let y = 0; y < dimensions[1]; y++) {
        for (let z = 0; z < dimensions[2]; z++) {
          const intensity = Math.random(); // Replace with actual security data
          points.push(x - dimensions[0]/2, y - dimensions[1]/2, z - dimensions[2]/2);
          
          // Color based on threat level
          if (intensity > 0.8) {
            colors.push(1, 0, 0); // Red - Critical
          } else if (intensity > 0.6) {
            colors.push(1, 0.5, 0); // Orange - High
          } else if (intensity > 0.4) {
            colors.push(1, 1, 0); // Yellow - Medium
          } else {
            colors.push(0, 1, 0); // Green - Low
          }
        }
      }
    }
    
    return { points: new Float32Array(points), colors: new Float32Array(colors) };
  }, [dimensions, data]);

  return (
    <points ref={heatmapRef}>
      <bufferGeometry>
        <bufferAttribute
          attach="attributes-position"
          array={heatmapData.points}
          count={heatmapData.points.length / 3}
          itemSize={3}
        />
        <bufferAttribute
          attach="attributes-color"
          array={heatmapData.colors}
          count={heatmapData.colors.length / 3}
          itemSize={3}
        />
      </bufferGeometry>
      <pointsMaterial size={0.1} vertexColors transparent opacity={0.6} />
    </points>
  );
};

// Main 3D Visualization Component
const ImmersiveSecurityVisualization = ({ 
  networkData = [], 
  vulnerabilityData = [], 
  className = '',
  onNodeSelect,
  selectedNode = null 
}) => {
  const [viewMode, setViewMode] = useState('network'); // 'network', 'heatmap', 'hybrid'
  const [showConnections, setShowConnections] = useState(true);
  const [animationSpeed, setAnimationSpeed] = useState(1);
  const [filterLevel, setFilterLevel] = useState('all');

  // Sample network data if none provided
  const defaultNetworkData = useMemo(() => [
    { id: 1, position: [0, 0, 0], type: 'server', threatLevel: 'high', vulnerabilities: ['SQL Injection', 'XSS'] },
    { id: 2, position: [3, 2, 1], type: 'database', threatLevel: 'critical', vulnerabilities: ['Weak Authentication'] },
    { id: 3, position: [-2, 1, 3], type: 'endpoint', threatLevel: 'medium', vulnerabilities: [] },
    { id: 4, position: [1, -2, -1], type: 'router', threatLevel: 'low', vulnerabilities: [] },
    { id: 5, position: [-3, -1, 2], type: 'firewall', threatLevel: 'medium', vulnerabilities: ['Outdated Rules'] }
  ], []);

  const nodes = networkData.length > 0 ? networkData : defaultNetworkData;

  const connections = useMemo(() => [
    { start: [0, 0, 0], end: [3, 2, 1], threatLevel: 'high' },
    { start: [0, 0, 0], end: [-2, 1, 3], threatLevel: 'medium' },
    { start: [3, 2, 1], end: [1, -2, -1], threatLevel: 'low' },
    { start: [-2, 1, 3], end: [-3, -1, 2], threatLevel: 'medium' }
  ], []);

  const filteredNodes = useMemo(() => {
    if (filterLevel === 'all') return nodes;
    return nodes.filter(node => node.threatLevel === filterLevel);
  }, [nodes, filterLevel]);

  return (
    <QuantumGlassCard variant="elevated" className={`h-[600px] ${className}`}>
      {/* Controls */}
      <div className="p-4 border-b border-white/10">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white">3D Security Visualization</h3>
          
          <div className="flex items-center space-x-2">
            <select
              value={viewMode}
              onChange={(e) => setViewMode(e.target.value)}
              className="px-3 py-1 bg-white/10 border border-white/20 rounded-lg text-white text-sm"
            >
              <option value="network">Network Topology</option>
              <option value="heatmap">Security Heatmap</option>
              <option value="hybrid">Hybrid View</option>
            </select>
            
            <select
              value={filterLevel}
              onChange={(e) => setFilterLevel(e.target.value)}
              className="px-3 py-1 bg-white/10 border border-white/20 rounded-lg text-white text-sm"
            >
              <option value="all">All Threats</option>
              <option value="critical">Critical Only</option>
              <option value="high">High & Above</option>
              <option value="medium">Medium & Above</option>
            </select>
          </div>
        </div>

        <div className="flex items-center space-x-4 text-sm">
          <label className="flex items-center space-x-2 text-gray-300">
            <input
              type="checkbox"
              checked={showConnections}
              onChange={(e) => setShowConnections(e.target.checked)}
              className="rounded"
            />
            <span>Show Connections</span>
          </label>
          
          <div className="flex items-center space-x-2 text-gray-300">
            <span>Animation Speed:</span>
            <input
              type="range"
              min="0.1"
              max="2"
              step="0.1"
              value={animationSpeed}
              onChange={(e) => setAnimationSpeed(parseFloat(e.target.value))}
              className="w-20"
            />
            <span>{animationSpeed}x</span>
          </div>
        </div>
      </div>

      {/* 3D Canvas */}
      <div className="flex-1 relative">
        <Canvas
          camera={{ position: [10, 10, 10], fov: 60 }}
          style={{ background: 'transparent' }}
        >
          <Environment preset="night" />
          
          {/* Lighting */}
          <ambientLight intensity={0.3} />
          <pointLight position={[10, 10, 10]} intensity={0.8} />
          <pointLight position={[-10, -10, -10]} intensity={0.4} color="#0EA5E9" />

          {/* Network Nodes */}
          {(viewMode === 'network' || viewMode === 'hybrid') && (
            <>
              {filteredNodes.map((node) => (
                <NetworkNode
                  key={node.id}
                  position={node.position}
                  threatLevel={node.threatLevel}
                  nodeType={node.type}
                  vulnerabilities={node.vulnerabilities}
                  isSelected={selectedNode === node.id}
                  onClick={() => onNodeSelect?.(node)}
                />
              ))}

              {/* Network Connections */}
              {showConnections && connections.map((connection, index) => (
                <NetworkConnection
                  key={index}
                  start={connection.start}
                  end={connection.end}
                  threatLevel={connection.threatLevel}
                  animated={animationSpeed > 0}
                />
              ))}
            </>
          )}

          {/* Security Heatmap */}
          {(viewMode === 'heatmap' || viewMode === 'hybrid') && (
            <SecurityHeatmap data={vulnerabilityData} />
          )}

          {/* Post-processing effects removed - requires @react-three/postprocessing */}

          <OrbitControls 
            enablePan={true} 
            enableZoom={true} 
            enableRotate={true}
            autoRotate={animationSpeed > 0}
            autoRotateSpeed={animationSpeed * 2}
          />
        </Canvas>

        {/* Legend */}
        <div className="absolute bottom-4 left-4 bg-black/80 backdrop-blur-sm rounded-lg p-3">
          <h4 className="text-white font-semibold mb-2">Threat Levels</h4>
          <div className="space-y-1 text-xs">
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-green-500 rounded"></div>
              <span className="text-gray-300">Low Risk</span>
            </div>
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-yellow-500 rounded"></div>
              <span className="text-gray-300">Medium Risk</span>
            </div>
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-red-500 rounded"></div>
              <span className="text-gray-300">High Risk</span>
            </div>
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-purple-500 rounded"></div>
              <span className="text-gray-300">Critical Risk</span>
            </div>
          </div>
        </div>

        {/* Node Info Panel */}
        {selectedNode && (
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            className="absolute top-4 right-4 bg-black/80 backdrop-blur-sm rounded-lg p-4 max-w-xs"
          >
            <h4 className="text-white font-semibold mb-2">Node Details</h4>
            <div className="text-sm text-gray-300 space-y-1">
              <p><strong>Type:</strong> {nodes.find(n => n.id === selectedNode)?.type}</p>
              <p><strong>Threat Level:</strong> {nodes.find(n => n.id === selectedNode)?.threatLevel}</p>
              <p><strong>Vulnerabilities:</strong> {nodes.find(n => n.id === selectedNode)?.vulnerabilities.length || 0}</p>
            </div>
          </motion.div>
        )}
      </div>
    </QuantumGlassCard>
  );
};

export default ImmersiveSecurityVisualization;
