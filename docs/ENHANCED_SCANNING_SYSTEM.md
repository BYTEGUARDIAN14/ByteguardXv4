# Enhanced Scanning System Documentation

## Overview

The Enhanced Scanning System in ByteGuardX provides industry-grade vulnerability detection with advanced accuracy, result integrity, and explainable AI capabilities. This system integrates multiple scanning engines, ML-powered validation, plugin trust scoring, and comprehensive result verification.

## Architecture

### Core Components

1. **Unified Scanner** (`byteguardx/core/unified_scanner.py`)
   - Orchestrates all scanning components
   - Provides hybrid static + dynamic analysis
   - Supports multiple scan modes and configurations
   - Implements result caching and performance optimization

2. **Result Verification System** (`byteguardx/validation/verify_scan_results.py`)
   - Cross-validates findings between scanners
   - Performs temporal consistency checks
   - Validates pattern accuracy
   - Provides confidence scoring

3. **Plugin Trust Scoring** (`byteguardx/validation/plugin_result_trust_score.py`)
   - Evaluates plugin reliability and trustworthiness
   - Tracks plugin performance metrics
   - Integrates user feedback
   - Provides risk assessment

4. **Enhanced Frontend** (`src/components/ScanResults.jsx`)
   - Displays verification status for each finding
   - Provides explainable AI insights
   - Offers advanced filtering and search
   - Shows confidence breakdowns and feature importance

## Key Features

### 1. Hybrid Scanning Modes

```python
from byteguardx.core.unified_scanner import ScanMode

# Available scan modes
ScanMode.STATIC_ONLY      # Pattern-based detection only
ScanMode.DYNAMIC_ONLY     # Behavioral analysis only
ScanMode.HYBRID           # Combined static + dynamic
ScanMode.ML_ENHANCED      # ML-powered analysis
ScanMode.COMPREHENSIVE    # All techniques combined
ScanMode.FAST             # Optimized for speed
```

### 2. Verification Status Levels

- **Verified**: High confidence, cross-validated findings
- **Cross-Validated**: Confirmed by multiple scanners
- **Unverified**: Single scanner detection
- **Pending**: Awaiting verification
- **Failed**: Verification failed

### 3. Trust Scoring for Plugins

```python
from byteguardx.validation.plugin_result_trust_score import TrustLevel

# Trust levels
TrustLevel.VERY_HIGH    # 90%+ reliability
TrustLevel.HIGH         # 75-90% reliability
TrustLevel.MEDIUM       # 60-75% reliability
TrustLevel.LOW          # 40-60% reliability
TrustLevel.VERY_LOW     # <40% reliability
```

## Usage Examples

### Basic Unified Scanning

```python
from byteguardx.core.unified_scanner import UnifiedScanner, ScanContext, ScanMode

# Initialize scanner
scanner = UnifiedScanner()

# Create scan context
context = ScanContext(
    file_path="example.py",
    content="api_key = 'sk-1234567890abcdef'",
    language="python",
    file_size=100,
    scan_mode=ScanMode.COMPREHENSIVE,
    confidence_threshold=0.7,
    enable_ml=True,
    enable_plugins=True,
    enable_cross_validation=True
)

# Perform scan
findings = scanner.scan_content(context)

# Process results
for finding in findings:
    print(f"Type: {finding.type}")
    print(f"Confidence: {finding.confidence:.2f}")
    print(f"Verification: {finding.verification_status}")
    print(f"Explanation: {finding.explanation}")
```

### Advanced API Usage

```bash
# Enhanced unified scanning endpoint
curl -X POST http://localhost:5000/api/v2/scan/unified \
  -H "Content-Type: application/json" \
  -d '{
    "content": "password = \"hardcoded_secret\"",
    "file_path": "config.py",
    "scan_mode": "comprehensive",
    "enable_verification": true,
    "enable_explanations": true,
    "confidence_threshold": 0.7
  }'
```

### Result Verification

```python
from byteguardx.validation.verify_scan_results import ResultVerifier

verifier = ResultVerifier()

# Verify single finding
finding = {
    "type": "secret",
    "file_path": "config.py",
    "line_number": 10,
    "description": "Hardcoded API key"
}

verification_report = verifier.verify_finding(finding)
print(f"Verification Result: {verification_report.verification_result}")
print(f"Confidence Score: {verification_report.confidence_score}")
```

### Plugin Trust Management

```python
from byteguardx.validation.plugin_result_trust_score import PluginTrustScorer

scorer = PluginTrustScorer()

# Calculate trust score
trust_score = scorer.calculate_trust_score("my_plugin")
print(f"Trust Level: {trust_score.trust_level}")
print(f"Risk Category: {trust_score.risk_category}")

# Get trusted plugins
trusted_plugins = scorer.get_trusted_plugins(TrustLevel.MEDIUM)
```

## Configuration

### Scanner Configuration

```python
config = {
    'entropy_threshold': 3.5,
    'confidence_threshold': 0.6,
    'enable_cross_validation': True,
    'enable_context_analysis': True,
    'max_processing_time': 30.0
}

scanner = UnifiedScanner(config)
```

### Verification Thresholds

```python
verifier_config = {
    'cross_scanner_agreement': 0.7,
    'temporal_consistency': 0.8,
    'pattern_confidence': 0.6,
    'context_relevance': 0.5,
    'ml_validation': 0.7
}

verifier = ResultVerifier(verifier_config)
```

## Performance Optimization

### Caching

The system implements intelligent caching:
- Result caching for identical content
- Pattern caching for regex optimization
- Context caching for repeated analysis

### Parallel Processing

```python
import asyncio

# Asynchronous scanning for better performance
findings = await scanner.scan_content_async(context)
```

### Performance Monitoring

```python
# Get performance statistics
stats = scanner.get_scan_statistics()
print(f"Average processing time: {stats['avg_processing_time']:.2f}s")
print(f"Cache hit rate: {stats['cache_hits']}/{stats['total_scans']}")
```

## Frontend Integration

### Enhanced Results Display

The frontend now includes:

1. **Verification Status Indicators**
   - Color-coded badges for verification status
   - Icons for different verification levels
   - Filtering by verification status

2. **Explainable AI Features**
   - Confidence breakdown visualization
   - Feature importance charts
   - Detection method explanations
   - Similar pattern analysis

3. **Advanced Filtering**
   - Filter by verification status
   - Search across multiple fields
   - Combined severity and status filters

### Usage in React Components

```jsx
import { ScanResults } from './components/ScanResults'

// Enhanced results with verification and explanations
<ScanResults 
  results={{
    findings: enhancedFindings,
    verification_stats: verificationStats,
    scan_metadata: scanMetadata
  }}
/>
```

## Security Considerations

### Input Validation

All inputs are validated and sanitized:
- Content size limits (10MB default)
- File path validation
- Parameter sanitization

### Plugin Sandboxing

Plugins are executed in isolated environments:
- Resource limits
- Network restrictions
- File system isolation

### Audit Logging

All scanning activities are logged:
- Scan requests and results
- Verification decisions
- Plugin executions
- User feedback

## Monitoring and Alerting

### Health Checks

```python
# Check system health
health_status = scanner.get_health_status()
```

### Performance Metrics

Key metrics tracked:
- Scan completion time
- False positive rates
- Verification accuracy
- Plugin reliability

### Alerting

Alerts are triggered for:
- High false positive rates
- Plugin failures
- Performance degradation
- Security violations

## Troubleshooting

### Common Issues

1. **High False Positive Rate**
   - Adjust confidence thresholds
   - Enable cross-validation
   - Update pattern rules

2. **Slow Performance**
   - Use FAST scan mode
   - Increase cache size
   - Disable heavy plugins

3. **Plugin Trust Issues**
   - Review plugin metrics
   - Check user feedback
   - Update plugin versions

### Debug Mode

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Enable detailed logging
scanner = UnifiedScanner({'debug': True})
```

## API Reference

### Unified Scanner API

#### POST /api/v2/scan/unified

Enhanced scanning endpoint with full feature support.

**Request:**
```json
{
  "content": "string",
  "file_path": "string",
  "scan_mode": "comprehensive|fast|static_only|dynamic_only|hybrid|ml_enhanced",
  "enable_verification": true,
  "enable_explanations": true,
  "confidence_threshold": 0.7,
  "enable_ml": true,
  "enable_plugins": true,
  "enable_cross_validation": true
}
```

**Response:**
```json
{
  "scan_id": "uuid",
  "status": "completed",
  "findings": [...],
  "summary": {...},
  "verification_reports": [...],
  "scan_metadata": {...},
  "statistics": {...}
}
```

### Verification API

#### POST /api/verify/finding

Verify a specific finding.

#### GET /api/verify/statistics

Get verification statistics.

### Trust Scoring API

#### GET /api/plugins/trust-scores

Get trust scores for all plugins.

#### POST /api/plugins/feedback

Submit plugin feedback.

## Best Practices

1. **Use appropriate scan modes** for different scenarios
2. **Enable cross-validation** for critical applications
3. **Monitor false positive rates** regularly
4. **Keep plugins updated** and reviewed
5. **Implement proper error handling** in integrations
6. **Use caching** for repeated scans
7. **Monitor performance metrics** continuously

## Future Enhancements

- Machine learning model improvements
- Advanced behavioral analysis
- Real-time collaborative filtering
- Enhanced plugin marketplace
- Automated remediation suggestions
- Integration with CI/CD pipelines
