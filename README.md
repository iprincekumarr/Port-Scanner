# Port Scanner 🔍

[![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)
[![Code Style](https://img.shields.io/badge/code%20style-pep8-orange.svg)](https://www.python.org/dev/peps/pep-0008/)

A feature-rich, multi-threaded port scanner written in Python with support for SYN scanning, UDP scanning, banner grabbing, OS fingerprinting, and network range scanning.

## 📋 Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [Scan Types](#scan-types)
- [Output Formats](#output-formats)
- [Advanced Features](#advanced-features)
- [Interactive Mode](#interactive-mode)
- [Requirements](#requirements)
- [Security Notice](#security-notice)
- [Contributing](#contributing)
- [License](#license)

## ✨ Features

- 🚀 **Multi-threaded Scanning** - Fast concurrent port scanning
- 🔒 **Multiple Scan Types**
  - TCP Connect (most compatible)
  - SYN Scan (stealth, requires root)
  - UDP Scan
- 🎯 **Network Range Scanning** - Scan entire subnets (CIDR notation)
- 📡 **Banner Grabbing** - Extract service versions and information
- 🖥️ **OS Fingerprinting** - Identify target operating systems
- 📊 **Progress Tracking** - Real-time progress bars with tqdm
- 📁 **Multiple Output Formats**
  - Text (human-readable)
  - JSON (machine-readable)
  - CSV (spreadsheet compatible)
  - XML (structured data)
- 🛡️ **Stealth Mode** - Random delays to avoid detection
- 🎨 **Color Output** - Easy-to-read terminal output
- 🖥️ **Interactive Mode** - User-friendly guided scanning

## 🚀 Installation

### Using pip (Recommended)

```bash
# Clone the repository
git clone https://github.com/iprincekumarr/Port-Scanner.git
cd Port-Scanner

# Install dependencies
pip install -r requirements.txt

# Make the script executable (Linux/Mac)
chmod +x port_scanner.py
