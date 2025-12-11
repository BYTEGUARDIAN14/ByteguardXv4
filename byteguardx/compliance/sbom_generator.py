"""
Software Bill of Materials (SBOM) Generator for ByteGuardX
Generates CycloneDX and SPDX format SBOMs for compliance and security tracking
"""

import os
import json
import logging
import hashlib
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum
import uuid

logger = logging.getLogger(__name__)

class SBOMFormat(Enum):
    """SBOM format types"""
    CYCLONE_DX = "cyclonedx"
    SPDX = "spdx"

class ComponentType(Enum):
    """Component types"""
    APPLICATION = "application"
    FRAMEWORK = "framework"
    LIBRARY = "library"
    CONTAINER = "container"
    OPERATING_SYSTEM = "operating-system"
    DEVICE = "device"
    FILE = "file"

@dataclass
class ComponentLicense:
    """Component license information"""
    license_id: str
    license_name: str
    license_url: Optional[str] = None

@dataclass
class ComponentVulnerability:
    """Component vulnerability information"""
    cve_id: str
    severity: str
    description: str
    cvss_score: Optional[float] = None
    fixed_version: Optional[str] = None

@dataclass
class SBOMComponent:
    """SBOM component information"""
    bom_ref: str
    name: str
    version: str
    component_type: ComponentType
    supplier: Optional[str] = None
    author: Optional[str] = None
    publisher: Optional[str] = None
    description: Optional[str] = None
    scope: str = "required"
    hashes: Optional[Dict[str, str]] = None
    licenses: Optional[List[ComponentLicense]] = None
    purl: Optional[str] = None  # Package URL
    external_references: Optional[List[Dict[str, str]]] = None
    vulnerabilities: Optional[List[ComponentVulnerability]] = None

@dataclass
class SBOMMetadata:
    """SBOM metadata information"""
    timestamp: datetime
    tools: List[Dict[str, str]]
    authors: List[Dict[str, str]]
    component: SBOMComponent
    properties: Optional[Dict[str, str]] = None

class SBOMGenerator:
    """Generates Software Bill of Materials in various formats"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent.parent
        self.version = "1.0.0"
        self.namespace = "https://byteguardx.com"
        
    def generate_sbom(self, format_type: SBOMFormat = SBOMFormat.CYCLONE_DX,
                     include_vulnerabilities: bool = True,
                     include_licenses: bool = True) -> Dict[str, Any]:
        """
        Generate SBOM for ByteGuardX
        
        Args:
            format_type: SBOM format (CycloneDX or SPDX)
            include_vulnerabilities: Include vulnerability information
            include_licenses: Include license information
            
        Returns:
            Dict containing SBOM data
        """
        try:
            # Collect component information
            components = self._collect_components(include_vulnerabilities, include_licenses)
            
            # Generate metadata
            metadata = self._generate_metadata()
            
            if format_type == SBOMFormat.CYCLONE_DX:
                return self._generate_cyclonedx_sbom(metadata, components)
            elif format_type == SBOMFormat.SPDX:
                return self._generate_spdx_sbom(metadata, components)
            else:
                raise ValueError(f"Unsupported SBOM format: {format_type}")
                
        except Exception as e:
            logger.error(f"SBOM generation failed: {e}")
            raise
    
    def save_sbom(self, sbom_data: Dict[str, Any], output_path: str) -> str:
        """
        Save SBOM to file
        
        Args:
            sbom_data: SBOM data dictionary
            output_path: Output file path
            
        Returns:
            Path to saved file
        """
        try:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w') as f:
                json.dump(sbom_data, f, indent=2, default=str)
            
            logger.info(f"SBOM saved to {output_file}")
            return str(output_file)
            
        except Exception as e:
            logger.error(f"Failed to save SBOM: {e}")
            raise
    
    def _collect_components(self, include_vulnerabilities: bool = True,
                          include_licenses: bool = True) -> List[SBOMComponent]:
        """Collect all components and dependencies"""
        components = []
        
        # Main application component
        main_component = SBOMComponent(
            bom_ref="byteguardx-main",
            name="ByteGuardX",
            version=self.version,
            component_type=ComponentType.APPLICATION,
            supplier="ByteGuardX Team",
            author="ByteGuardX Team",
            description="AI-powered code security platform",
            hashes=self._calculate_project_hashes(),
            licenses=[ComponentLicense("MIT", "MIT License")] if include_licenses else None,
            external_references=[
                {"type": "website", "url": "https://byteguardx.com"},
                {"type": "vcs", "url": "https://github.com/byteguardx/byteguardx"}
            ]
        )
        components.append(main_component)
        
        # Python dependencies
        python_deps = self._collect_python_dependencies(include_vulnerabilities, include_licenses)
        components.extend(python_deps)
        
        # JavaScript dependencies (if any)
        js_deps = self._collect_javascript_dependencies(include_vulnerabilities, include_licenses)
        components.extend(js_deps)
        
        # System dependencies
        system_deps = self._collect_system_dependencies(include_licenses)
        components.extend(system_deps)
        
        return components
    
    def _collect_python_dependencies(self, include_vulnerabilities: bool,
                                   include_licenses: bool) -> List[SBOMComponent]:
        """Collect Python package dependencies"""
        components = []
        
        try:
            # Try to get installed packages
            result = subprocess.run(['pip', 'list', '--format=json'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                packages = json.loads(result.stdout)
                
                for package in packages:
                    name = package['name']
                    version = package['version']
                    
                    # Skip standard library packages
                    if name in ['pip', 'setuptools', 'wheel']:
                        continue
                    
                    component = SBOMComponent(
                        bom_ref=f"python-{name}-{version}",
                        name=name,
                        version=version,
                        component_type=ComponentType.LIBRARY,
                        purl=f"pkg:pypi/{name}@{version}",
                        licenses=self._get_package_license(name) if include_licenses else None,
                        vulnerabilities=self._get_package_vulnerabilities(name, version) if include_vulnerabilities else None
                    )
                    components.append(component)
                    
        except Exception as e:
            logger.warning(f"Failed to collect Python dependencies: {e}")
        
        return components
    
    def _collect_javascript_dependencies(self, include_vulnerabilities: bool,
                                       include_licenses: bool) -> List[SBOMComponent]:
        """Collect JavaScript/Node.js dependencies"""
        components = []
        
        # Check for package.json in portal directory
        package_json_path = self.project_root / "portal" / "package.json"
        
        if package_json_path.exists():
            try:
                with open(package_json_path, 'r') as f:
                    package_data = json.load(f)
                
                dependencies = package_data.get('dependencies', {})
                dev_dependencies = package_data.get('devDependencies', {})
                
                all_deps = {**dependencies, **dev_dependencies}
                
                for name, version in all_deps.items():
                    # Clean version string
                    clean_version = version.lstrip('^~>=<')
                    
                    component = SBOMComponent(
                        bom_ref=f"npm-{name}-{clean_version}",
                        name=name,
                        version=clean_version,
                        component_type=ComponentType.LIBRARY,
                        purl=f"pkg:npm/{name}@{clean_version}",
                        scope="required" if name in dependencies else "optional"
                    )
                    components.append(component)
                    
            except Exception as e:
                logger.warning(f"Failed to collect JavaScript dependencies: {e}")
        
        return components
    
    def _collect_system_dependencies(self, include_licenses: bool) -> List[SBOMComponent]:
        """Collect system-level dependencies"""
        components = []
        
        # Docker base images
        docker_images = [
            {"name": "python", "version": "3.11-alpine", "type": "container"},
            {"name": "nginx", "version": "alpine", "type": "container"},
            {"name": "redis", "version": "7-alpine", "type": "container"},
            {"name": "postgres", "version": "15-alpine", "type": "container"}
        ]
        
        for image in docker_images:
            component = SBOMComponent(
                bom_ref=f"docker-{image['name']}-{image['version']}",
                name=image['name'],
                version=image['version'],
                component_type=ComponentType.CONTAINER,
                purl=f"pkg:docker/{image['name']}@{image['version']}"
            )
            components.append(component)
        
        return components
    
    def _generate_metadata(self) -> SBOMMetadata:
        """Generate SBOM metadata"""
        main_component = SBOMComponent(
            bom_ref="byteguardx-root",
            name="ByteGuardX",
            version=self.version,
            component_type=ComponentType.APPLICATION,
            supplier="ByteGuardX Team",
            description="AI-powered code security platform"
        )
        
        metadata = SBOMMetadata(
            timestamp=datetime.now(),
            tools=[
                {
                    "vendor": "ByteGuardX",
                    "name": "SBOM Generator",
                    "version": "1.0.0"
                }
            ],
            authors=[
                {
                    "name": "ByteGuardX Team",
                    "email": "security@byteguardx.com"
                }
            ],
            component=main_component,
            properties={
                "build_system": "Python setuptools",
                "build_date": datetime.now().isoformat(),
                "security_scan_date": datetime.now().isoformat()
            }
        )
        
        return metadata
    
    def _generate_cyclonedx_sbom(self, metadata: SBOMMetadata, 
                               components: List[SBOMComponent]) -> Dict[str, Any]:
        """Generate CycloneDX format SBOM"""
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": metadata.timestamp.isoformat(),
                "tools": metadata.tools,
                "authors": metadata.authors,
                "component": asdict(metadata.component),
                "properties": [
                    {"name": k, "value": v} for k, v in (metadata.properties or {}).items()
                ]
            },
            "components": [
                self._component_to_cyclonedx(comp) for comp in components
            ]
        }
        
        return sbom
    
    def _generate_spdx_sbom(self, metadata: SBOMMetadata,
                          components: List[SBOMComponent]) -> Dict[str, Any]:
        """Generate SPDX format SBOM"""
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "ByteGuardX-SBOM",
            "documentNamespace": f"{self.namespace}/sbom/{uuid.uuid4()}",
            "creationInfo": {
                "created": metadata.timestamp.isoformat(),
                "creators": [f"Tool: {tool['name']}-{tool['version']}" for tool in metadata.tools],
                "licenseListVersion": "3.19"
            },
            "packages": [
                self._component_to_spdx(comp) for comp in components
            ]
        }
        
        return sbom
    
    def _component_to_cyclonedx(self, component: SBOMComponent) -> Dict[str, Any]:
        """Convert component to CycloneDX format"""
        cyclone_comp = {
            "bom-ref": component.bom_ref,
            "type": component.component_type.value,
            "name": component.name,
            "version": component.version,
            "scope": component.scope
        }
        
        if component.supplier:
            cyclone_comp["supplier"] = {"name": component.supplier}
        
        if component.author:
            cyclone_comp["author"] = component.author
        
        if component.description:
            cyclone_comp["description"] = component.description
        
        if component.hashes:
            cyclone_comp["hashes"] = [
                {"alg": alg, "content": hash_val} 
                for alg, hash_val in component.hashes.items()
            ]
        
        if component.licenses:
            cyclone_comp["licenses"] = [
                {"license": {"id": lic.license_id, "name": lic.license_name}}
                for lic in component.licenses
            ]
        
        if component.purl:
            cyclone_comp["purl"] = component.purl
        
        if component.external_references:
            cyclone_comp["externalReferences"] = component.external_references
        
        return cyclone_comp
    
    def _component_to_spdx(self, component: SBOMComponent) -> Dict[str, Any]:
        """Convert component to SPDX format"""
        spdx_comp = {
            "SPDXID": f"SPDXRef-{component.bom_ref}",
            "name": component.name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "copyrightText": "NOASSERTION"
        }
        
        if component.version:
            spdx_comp["versionInfo"] = component.version
        
        if component.supplier:
            spdx_comp["supplier"] = f"Organization: {component.supplier}"
        
        if component.licenses:
            spdx_comp["licenseConcluded"] = component.licenses[0].license_id
            spdx_comp["licenseDeclared"] = component.licenses[0].license_id
        
        if component.external_references:
            homepage = next((ref["url"] for ref in component.external_references 
                           if ref["type"] == "website"), None)
            if homepage:
                spdx_comp["homepage"] = homepage
        
        return spdx_comp
    
    def _calculate_project_hashes(self) -> Dict[str, str]:
        """Calculate hashes for the main project"""
        try:
            # Calculate SHA-256 hash of main Python files
            main_files = list(self.project_root.glob("byteguardx/**/*.py"))
            
            hasher = hashlib.sha256()
            for file_path in sorted(main_files):
                if file_path.is_file():
                    with open(file_path, 'rb') as f:
                        hasher.update(f.read())
            
            return {
                "SHA-256": hasher.hexdigest()
            }
            
        except Exception as e:
            logger.warning(f"Failed to calculate project hashes: {e}")
            return {}
    
    def _get_package_license(self, package_name: str) -> List[ComponentLicense]:
        """Get license information for a package"""
        try:
            # Try to get license info from pip show
            result = subprocess.run(['pip', 'show', package_name], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith('License:'):
                        license_name = line.split(':', 1)[1].strip()
                        if license_name and license_name != 'UNKNOWN':
                            return [ComponentLicense(license_name, license_name)]
            
            return [ComponentLicense("UNKNOWN", "Unknown License")]
            
        except Exception:
            return [ComponentLicense("UNKNOWN", "Unknown License")]
    
    def _get_package_vulnerabilities(self, package_name: str, 
                                   version: str) -> List[ComponentVulnerability]:
        """Get vulnerability information for a package"""
        # This would integrate with vulnerability databases
        # For now, return empty list
        return []

# Global instance
sbom_generator = SBOMGenerator()
