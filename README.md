<div align="center">
  <img src="https://raw.githubusercontent.com/tandpfun/skill-icons/65dea6c4eaca7da319e552c09f4cf5a9a8dab2c2/icons/Security.svg" alt="Security Logo" width="120" height="120" />
  
  <br/>
  <br/>
  
  <h1>ByteguardX v4</h1>
  
  <p>
    <b>The Ultimate Offline-First Security Scanner & Extensible Vulnerability Ecosystem</b>
  </p>
  
  <p>
    <a href="#features">
      <img src="https://img.shields.io/badge/SECURITY-ANALYSIS-000000?style=for-the-badge&logo=shield&logoColor=white" alt="Security">
    </a>
    <a href="#architecture">
      <img src="https://img.shields.io/badge/TAURI_RUST-CORE-000000?style=for-the-badge&logo=rust&logoColor=white" alt="Rust Core">
    </a>
    <a href="#plugin-engine">
      <img src="https://img.shields.io/badge/PYTHON-PLUGINS-000000?style=for-the-badge&logo=python&logoColor=white" alt="Python Plugins">
    </a>
    <a href="#installation">
      <img src="https://img.shields.io/badge/LOCAL-FIRST-000000?style=for-the-badge&logo=server&logoColor=white" alt="Local First">
    </a>
  </p>

  <p>
    ByteguardX is a comprehensive, ultra-fast, totally offline security analysis tool designed for modern development workflows. Powered by a robust Rust core (via Tauri) and a sleek React Desktop UI, it provides deep vulnerability scanning, secret detection, and an extensible plugin marketplace without ever sending a single line of your code to the cloud.
  </p>
</div>

---

## <img src="https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/shield-halved.svg" width="20" height="20" style="filter: invert(1); vertical-align: middle; margin-right: 10px;"> Key Features

<table width="100%">
  <tr>
    <td width="50%" valign="top">
      <h3><img src="https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/desktop.svg" width="16" height="16" style="filter: invert(1); vertical-align: middle; margin-right: 6px;"> Native Desktop Feel</h3>
      <ul>
        <li><b>Tauri Powered:</b> Built with Tauri and React, delivering a highly optimized, flat, and responsive desktop-class user interface.</li>
        <li><b>Zero Electron Bloat:</b> Minimal memory footprint with native OS window management.</li>
        <li><b>Dark Mode First:</b> Aesthetically pleasing "desktop-panel" dark theme designed to reduce eye strain during deep security reading.</li>
      </ul>
    </td>
    <td width="50%" valign="top">
      <h3><img src="https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/wifi.svg" width="16" height="16" style="filter: invert(1); vertical-align: middle; margin-right: 6px;"> 100% Offline Analysis</h3>
      <ul>
        <li><b>Total Privacy:</b> ByteguardX operates completely locally. Your source code, secrets, and environment configurations never leave your machine.</li>
        <li><b>Air-Gapped Ready:</b> Perfect for enterprise environments with strict data exfiltration policies.</li>
        <li><b>Local DB:</b> Embedded SQLite database for lightning-fast historical scan lookups.</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <h3><img src="https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/microchip.svg" width="16" height="16" style="filter: invert(1); vertical-align: middle; margin-right: 6px;"> Heuristic Scanning Engine</h3>
      <ul>
        <li><b>Secret Detection:</b> Advanced pattern recognition identifies hardcoded secrets, high-entropy tokens, and API keys.</li>
        <li><b>CVE Analysis:</b> Dependency risk profiling with CVSS v3.1 scoring.</li>
        <li><b>AI Anti-Patterns:</b> Structural analysis to catch unsafe AI-generated code snippets and prompt injection vulnerabilities.</li>
      </ul>
    </td>
    <td width="50%" valign="top">
      <h3><img src="https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/boxes-stacked.svg" width="16" height="16" style="filter: invert(1); vertical-align: middle; margin-right: 6px;"> Extensible Plugin System</h3>
      <ul>
        <li><b>Plugin Marketplace:</b> Extend scanner capabilities dynamically. Browse and install community-verified security extensions.</li>
        <li><b>Python Integration:</b> Write custom Python testing modules directly within the app's IDE interface.</li>
        <li><b>Execution Monitor:</b> Real-time stdout/stderr streaming from your custom security scripts.</li>
      </ul>
    </td>
  </tr>
</table>

---

## <img src="https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/layer-group.svg" width="20" height="20" style="filter: invert(1); vertical-align: middle; margin-right: 10px;"> Tech Stack & Architecture

ByteguardX v4 utilizes a modern triad of Rust, React, and Python to deliver a seamless local security experience. 

<div align="center">
  <img src="https://img.shields.io/badge/Core-Tauri-24C8DB?style=for-the-badge&logo=tauri&logoColor=white" alt="Tauri">
  <img src="https://img.shields.io/badge/Backend-Rust-000000?style=for-the-badge&logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/Frontend-React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB" alt="React">
  <img src="https://img.shields.io/badge/Build-Vite-646CFF?style=for-the-badge&logo=vite&logoColor=white" alt="Vite">
  <img src="https://img.shields.io/badge/Plugins-Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Styling-Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white" alt="Tailwind CSS">
</div>

<br/>

<table width="100%">
  <tr>
    <td align="center" width="33%">
      <img src="https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/brands/rust.svg" width="48" height="48" style="filter: invert(1);"><br/>
      <b>Tauri Core (Rust)</b><br/>
      Handles secure filesystem access, OS-level window management, high-performance file hashing, and IPC routing.
    </td>
    <td align="center" width="33%">
      <img src="https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/brands/react.svg" width="48" height="48" style="filter: invert(1);"><br/>
      <b>Frontend (React)</b><br/>
      A dense, highly interactive UI rendering complex vulnerability heatmaps, scan progression lines, and realtime data tables.
    </td>
    <td align="center" width="33%">
      <img src="https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/brands/python.svg" width="48" height="48" style="filter: invert(1);"><br/>
      <b>Plugin Engine (Python)</b><br/>
      A bridged runtime environment allowing users to execute custom Python security heuristic scripts against local folders.
    </td>
  </tr>
</table>


---

## <img src="https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/magnifying-glass-chart.svg" width="20" height="20" style="filter: invert(1); vertical-align: middle; margin-right: 10px;"> Interface Deep Dive

ByteguardX uses a structured, flat-design architecture tailored for dense data visualization without visual clutter or unnecessary animations.

<table width="100%">
  <tr>
    <td width="33%" align="center">
      <img src="https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/chart-pie.svg" width="40" height="40" style="filter: invert(1); margin-bottom: 10px;">
      <br/>
      <b>Executive Dashboard</b><br/>
      Get a 10,000-foot view of your local repository's security posture. View global CVSS scores, critical issue distributions, and historical trends at a glance.
    </td>
    <td width="33%" align="center">
      <img src="https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/radar.svg" width="40" height="40" style="filter: invert(1); margin-bottom: 10px;">
      <br/>
      <b>Real-time Scanner</b><br/>
      Drag-and-drop file/folder analysis. Configure exclusion filters, set scan depths, and watch live progress bars as the Rust engine processes thousands of files.
    </td>
    <td width="33%" align="center">
      <img src="https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/table-list.svg" width="40" height="40" style="filter: invert(1); margin-bottom: 10px;">
      <br/>
      <b>Detailed Reporting</b><br/>
      Drill down into individual scan reports. Sort vulnerabilities by severity, trace exact line numbers in your code, and view actionable remediation steps.
    </td>
  </tr>
  <tr>
    <td width="33%" align="center">
      <img src="https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/plug.svg" width="40" height="40" style="filter: invert(1); margin-bottom: 10px;">
      <br/>
      <b>Plugin Market</b><br/>
      Browse, install, and configure custom security extensions locally. Need to scan specifically for AWS misconfigurations? Just write or install a plugin for it.
    </td>
    <td width="33%" align="center">
      <img src="https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/sliders.svg" width="40" height="40" style="filter: invert(1); margin-bottom: 10px;">
      <br/>
      <b>Admin Settings</b><br/>
      Control the core engine. Set file size limits, toggle multi-threading, configure local storage retention, and manage background notification alerts.
    </td>
    <td width="33%" align="center">
      <img src="https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/fire.svg" width="40" height="40" style="filter: invert(1); margin-bottom: 10px;">
      <br/>
      <b>Security Heatmap</b><br/>
      Visualize the "hot spots" in your repository. A dynamic tree-map shows exactly which folders and services carry the highest density of vulnerabilities.
    </td>
  </tr>
</table>

---

## <img src="https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/terminal.svg" width="20" height="20" style="filter: invert(1); vertical-align: middle; margin-right: 10px;"> Getting Started

### 1. Prerequisites
Ensure you have the following installed on your machine:
- [Node.js](https://nodejs.org/) (v16+)
- [Rust](https://www.rust-lang.org/tools/install) (latest stable)
- [Python](https://www.python.org/downloads/) (3.8+) - *Required for the Plugin Engine*

### 2. Local Installation

```bash
# Clone the repository
git clone https://github.com/BYTEGUARDIAN14/ByteguardXv4.git

# Navigate to project directory
cd ByteguardX

# Install frontend dependencies
npm install

# Start the development server (Tauri + React)
npm run tauri dev

# To build the production app executable for your OS:
npm run tauri build
```

---

## <img src="https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/handshake.svg" width="20" height="20" style="filter: invert(1); vertical-align: middle; margin-right: 10px;"> Contributing & Open Source

ByteguardX is designed to be extensible. We highly encourage community contributions to expand standard rule dictionaries and the plugin repository. 

1. **Fork the Project**
2. **Create your Feature Branch:** `git checkout -b feature/AmazingSecurityRule`
3. **Commit your Changes:** `git commit -m 'Add some AmazingSecurityRule'`
4. **Push to the Branch:** `git push origin feature/AmazingSecurityRule`
5. **Open a Pull Request**

---

<div align="center">
  <img src="https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.x/svgs/solid/user-shield.svg" width="48" height="48" style="filter: invert(1);">
  <p>
    <i>Engineered with modern tools for local, private, and uncompromising security.</i>
  </p>
</div>
