"""
Plan-and-Execute Pattern for Complex Scans
Advanced orchestration with dependency-aware scheduling
"""

import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Any
import time
import json
from concurrent.futures import ThreadPoolExecutor
import numpy as np

class ExecutionPhase(Enum):
    PLANNING = "planning"
    EXECUTING = "executing"
    RE_PLANNING = "re_planning"
    COMPLETED = "completed"
    FAILED = "failed"

@dataclass
class ExecutionPlan:
    scan_id: str
    phases: List['ExecutionStage'] = field(default_factory=list)
    dependencies: Dict[str, Set[str]] = field(default_factory=dict)
    resource_allocation: Dict[str, Dict[str, float]] = field(default_factory=dict)
    estimated_duration: float = 0.0
    complexity_score: float = 0.0
    
class PlannerAgent:
    """Analyzes code and creates optimized execution plans"""
    
    def __init__(self):
        self.performance_history = {}
        self.complexity_analyzer = CodeComplexityAnalyzer()
        
    async def create_execution_plan(self, scan_context: Dict[str, Any]) -> ExecutionPlan:
        """Create optimized execution plan based on analysis"""
        plan = ExecutionPlan(scan_id=scan_context['scan_id'])
        
        # Analyze code complexity
        complexity_metrics = await self._analyze_complexity(scan_context)
        plan.complexity_score = complexity_metrics['composite_score']
        
        # Create dependency-aware phases
        plan.phases = await self._create_execution_phases(complexity_metrics, scan_context)
        plan.dependencies = self._build_dependency_graph(plan.phases)
        plan.resource_allocation = self._allocate_resources(plan.phases, complexity_metrics)
        plan.estimated_duration = self._estimate_duration(plan.phases)
        
        return plan
    
    async def _analyze_complexity(self, scan_context: Dict[str, Any]) -> Dict[str, Any]:
        """Deep complexity analysis for optimal planning"""
        files = scan_context.get('files', [])
        
        metrics = {
            'file_count': len(files),
            'total_size': sum(f.get('size', 0) for f in files),
            'language_diversity': len(set(f.get('language', 'unknown') for f in files)),
            'ast_complexity': 0.0,
            'dependency_depth': 0.0,
            'security_surface': 0.0
        }
        
        # AST complexity analysis
        for file_info in files[:10]:  # Sample for performance
            if file_info.get('language') in ['python', 'javascript', 'java']:
                ast_score = await self.complexity_analyzer.analyze_ast_complexity(file_info)
                metrics['ast_complexity'] += ast_score
        
        metrics['ast_complexity'] /= max(len(files), 1)
        
        # Calculate composite score
        metrics['composite_score'] = (
            min(metrics['file_count'] / 1000, 1.0) * 0.3 +
            min(metrics['total_size'] / (10 * 1024 * 1024), 1.0) * 0.2 +
            min(metrics['language_diversity'] / 10, 1.0) * 0.2 +
            metrics['ast_complexity'] * 0.3
        )
        
        return metrics

class ExecutorActor:
    """Executes plan phases with fault tolerance"""
    
    def __init__(self, actor_id: str, fault_zone: 'FaultZone'):
        self.actor_id = actor_id
        self.fault_zone = fault_zone
        self.circuit_breaker = CircuitBreaker(failure_threshold=5, timeout=30)
        self.current_task = None
        
    async def execute_phase(self, phase: 'ExecutionStage', context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute phase with circuit breaker protection"""
        if not self.circuit_breaker.can_execute():
            raise ExecutionError(f"Circuit breaker open for actor {self.actor_id}")
        
        try:
            self.current_task = phase
            result = await self._execute_with_timeout(phase, context)
            self.circuit_breaker.record_success()
            return result
            
        except Exception as e:
            self.circuit_breaker.record_failure()
            await self.fault_zone.handle_failure(self.actor_id, e)
            raise

class ReplanningEngine:
    """Handles failures and dynamic route adjustments"""
    
    def __init__(self):
        self.adaptation_strategies = {
            'plugin_failure': self._handle_plugin_failure,
            'resource_exhaustion': self._handle_resource_exhaustion,
            'timeout': self._handle_timeout,
            'dependency_failure': self._handle_dependency_failure
        }
    
    async def replan_on_failure(self, original_plan: ExecutionPlan, 
                               failure_context: Dict[str, Any]) -> ExecutionPlan:
        """Create new plan based on failure analysis"""
        failure_type = failure_context.get('type', 'unknown')
        
        if failure_type in self.adaptation_strategies:
            return await self.adaptation_strategies[failure_type](original_plan, failure_context)
        
        # Default: retry with reduced parallelism
        return await self._create_conservative_plan(original_plan, failure_context)
    
    async def _handle_plugin_failure(self, plan: ExecutionPlan, context: Dict[str, Any]) -> ExecutionPlan:
        """Handle plugin-specific failures"""
        failed_plugin = context.get('plugin_name')
        
        # Remove failed plugin and find alternatives
        new_phases = []
        for phase in plan.phases:
            if failed_plugin in phase.plugins:
                # Find alternative plugins
                alternatives = await self._find_plugin_alternatives(failed_plugin, phase.category)
                if alternatives:
                    new_phase = phase.copy()
                    new_phase.plugins = [p for p in phase.plugins if p != failed_plugin] + alternatives
                    new_phases.append(new_phase)
            else:
                new_phases.append(phase)
        
        plan.phases = new_phases
        return plan