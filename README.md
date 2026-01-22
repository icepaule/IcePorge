# IcePorge

**Comprehensive Malware Analysis & Threat Intelligence Stack**

IcePorge is a modular, enterprise-grade malware analysis ecosystem that integrates dynamic sandboxing, static reverse engineering, threat intelligence feeds, and LLM-powered analysis into a cohesive workflow.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           THREAT INTELLIGENCE FEEDS                          │
│  URLhaus ── ThreatFox ── MalwareBazaar ── Hybrid Analysis ── Ransomware.live │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │
                    ┌─────────────────┴─────────────────┐
                    ▼                                   ▼
          ┌─────────────────┐                 ┌─────────────────┐
          │  MWDB-Feeder    │                 │   CAPE-Feed     │
          │  Multi-Source   │                 │  MalwareBazaar  │
          │  Aggregator     │                 │    Pipeline     │
          └────────┬────────┘                 └────────┬────────┘
                   │                                   │
                   ▼                                   ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                              ANALYSIS PLATFORM                                │
│  ┌────────────────────────────────┐    ┌────────────────────────────────┐   │
│  │         MWDB-Stack             │    │         CAPE Sandbox           │   │
│  │  ┌──────────┐ ┌─────────────┐  │    │  ┌──────────┐ ┌─────────────┐  │   │
│  │  │  MWDB    │ │   Karton    │  │    │  │ Dynamic  │ │   Static    │  │   │
│  │  │  Core    │ │ Orchestrator│  │    │  │ Analysis │ │  Analysis   │  │   │
│  │  └──────────┘ └─────────────┘  │    │  └──────────┘ └─────────────┘  │   │
│  │       │              │         │    │       │              │         │   │
│  │       └──────┬───────┘         │    │       └──────┬───────┘         │   │
│  │              ▼                 │    │              │                 │   │
│  │  ┌─────────────────────────┐   │    │              │                 │   │
│  │  │ karton-cape-submitter   │───┼────┼──────────────┘                 │   │
│  │  └─────────────────────────┘   │    │                                │   │
│  └────────────────────────────────┘    └────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────┘
                   │                                   │
                   └───────────────┬───────────────────┘
                                   ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                           AI-ENHANCED ANALYSIS                                │
│  ┌────────────────────────────────┐    ┌────────────────────────────────┐   │
│  │    Ghidra-Orchestrator        │    │       Malware-RAG              │   │
│  │  ┌──────────┐ ┌─────────────┐  │    │  ┌──────────┐ ┌─────────────┐  │   │
│  │  │ Ghidra   │ │   Ollama    │  │    │  │  Qdrant  │ │    LLM      │  │   │
│  │  │ Headless │ │   LLM       │  │    │  │ VectorDB │ │  Analysis   │  │   │
│  │  └──────────┘ └─────────────┘  │    │  └──────────┘ └─────────────┘  │   │
│  └────────────────────────────────┘    └────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
                    ┌─────────────────────────────┐
                    │           MISP              │
                    │   Threat Intelligence       │
                    │        Platform             │
                    └─────────────────────────────┘
```

---

## Components

| Repository | Description | Status |
|------------|-------------|--------|
| [IcePorge-MWDB-Stack](https://github.com/icepaule/IcePorge-MWDB-Stack) | MWDB-core with Karton orchestration | ✅ Active |
| [IcePorge-MWDB-Feeder](https://github.com/icepaule/IcePorge-MWDB-Feeder) | Multi-source malware aggregator | ✅ Active |
| [IcePorge-CAPE-Feed](https://github.com/icepaule/IcePorge-CAPE-Feed) | MalwareBazaar → CAPE → MISP pipeline | ✅ Active |
| [IcePorge-CAPE-Mailer](https://github.com/icepaule/IcePorge-CAPE-Mailer) | Email-triggered analysis | ✅ Active |
| [IcePorge-Cockpit](https://github.com/icepaule/IcePorge-Cockpit) | Web management UI | ✅ Active |
| [IcePorge-Ghidra-Orchestrator](https://github.com/icepaule/IcePorge-Ghidra-Orchestrator) | Automated reverse engineering | ✅ Active |
| [IcePorge-Malware-RAG](https://github.com/icepaule/IcePorge-Malware-RAG) | LLM-powered analysis | ✅ Active |

---

## Features

### Threat Intelligence Ingestion
- **URLhaus** - Malicious URL and payload collection
- **ThreatFox** - IOC aggregation with sample downloads
- **MalwareBazaar** - Malware sample repository integration
- **Hybrid Analysis** - Falcon Sandbox public feed
- **Ransomware.live** - Ransomware gang tracking and YARA rules

### Dynamic Analysis
- **CAPE Sandbox** - Advanced malware behavior analysis
- **Automated submission** - Tag-based routing and prefiltering
- **MISP integration** - Automatic IOC export

### Static Analysis
- **Ghidra Headless** - Automated decompilation and analysis
- **LLM Enhancement** - AI-powered code understanding
- **API Extraction** - Automated function and string analysis

### Orchestration
- **Karton Framework** - CERT Polska's distributed task system
- **MWDB** - Malware database with sample correlation
- **Automated pipelines** - Feed → Analysis → Report

### AI-Enhanced Analysis
- **Ollama Integration** - Local LLM inference
- **RAG Pipeline** - Retrieval-augmented generation for malware context
- **Qdrant Vector DB** - Semantic similarity search

---

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Ubuntu 22.04+ / Debian 12+
- Minimum 32GB RAM, 500GB storage
- GPU recommended for LLM inference

### Installation

1. Clone the main repository:
```bash
git clone https://github.com/icepaule/IcePorge.git
cd IcePorge
```

2. Clone component repositories:
```bash
./scripts/clone-all.sh
```

3. Configure environment files:
```bash
# Copy example configs
cp component/.env.example component/.env
# Edit with your API keys and settings
```

4. Start the stack:
```bash
docker compose up -d
```

See individual component READMEs for detailed setup instructions.

---

## Configuration

All sensitive configuration (API keys, passwords, credentials) is stored in `.env` files which are **never committed** to the repository. Each component includes a `.env.example` template.

### Required API Keys

| Service | Registration URL | Used By |
|---------|------------------|---------|
| abuse.ch | https://auth.abuse.ch/ | MWDB-Feeder, CAPE-Feed |
| Hybrid Analysis | https://www.hybrid-analysis.com/signup | MWDB-Feeder |
| MISP | Your MISP instance | CAPE-Feed |
| Ransomware.live | https://www.ransomware.live/ | CAPE-Feed |

---

## Management

### Cockpit Web UI
Access the management interface at `https://your-server:9090/`

- **CAPE Sandbox** - Service status, VM management, logs
- **MWDB Stack** - Container status, Karton pipeline, feed sources

### Sync Script
Automatic synchronization to GitHub:
```bash
# Manual sync
/opt/iceporge/sync-to-github.sh

# Dry run (preview changes)
/opt/iceporge/sync-to-github.sh --dry-run

# Add to crontab (daily at 2:00 AM)
0 2 * * * /opt/iceporge/sync-to-github.sh >> /var/log/iceporge-sync.log 2>&1
```

---

## Security Considerations

- All API keys and credentials are stored in `.env` files (excluded from git)
- Network isolation recommended between analysis VMs and production
- TLS encryption for all external communications
- Regular updates of signature databases and YARA rules

---

## License

MIT License with Attribution - see [LICENSE](LICENSE)

Copyright (c) 2024-2026 IcePorge Project

**Author:** Michael Pauli
- GitHub: [@icepaule](https://github.com/icepaule)
- Email: info@mpauli.de

---

## Contributing

Contributions are welcome! Please read the contributing guidelines in each component repository.

## Support

- Open an issue in the relevant component repository
- Email: info@mpauli.de
