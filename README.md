# 🛡️ Modern Cloud-Native Kerberos: Passwordless & High-Availability Implementation

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=flat&logo=docker&logoColor=white)](https://docker.com)
[![React](https://img.shields.io/badge/react-%2320232a.svg?style=flat&logo=react&logoColor=%2361DAFB)](https://reactjs.org)

A revolutionary implementation of the Kerberos authentication protocol that eliminates passwords, achieves high availability, and embraces modern cloud-native architecture. This project addresses the fundamental weaknesses of traditional Kerberos implementations through innovative design patterns and contemporary technologies.

## 🚀 Executive Summary

This project implements a **passwordless**, **highly available**, and **microservice-based** Kerberos authentication system. We replace traditional password-based authentication with PKINIT (Public Key Cryptography for Initial Authentication), implement Primary-Replica KDC architecture for zero downtime, and modernize the entire stack with API-driven provisioning and a React-based user interface.

### 🎯 Key Innovations

- **True Passwordless Authentication**: PKINIT implementation using X.509 certificates
- **High Availability**: Primary-Replica KDC architecture with automatic failover
- **Microservice Architecture**: Dockerized, API-driven, cloud-native design
- **Multi-Device Support**: Zero-trust device approval workflow
- **Modern UI**: React frontend with WebCrypto API integration

## 📋 Table of Contents

- [Architecture Overview](#-architecture-overview)
- [Technology Stack](#-technology-stack)
- [Quick Start](#-quick-start)
- [Service Components](#-service-components)
- [Security Features](#-security-features)
- [Authentication Flow](#-authentication-flow)
- [Multi-Device Workflow](#-multi-device-workflow)
- [Database Schema](#-database-schema)
- [Configuration](#-configuration)
- [Development Guide](#-development-guide)
- [API Documentation](#-api-documentation)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)

## 🏗️ Architecture Overview

### System Architecture Diagram

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React Client  │    │  Python Client  │    │   Mobile App    │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   CA Server     │ ← Certificate Authority
                    │   (Port 5000)   │   Issues X.509 Certificates
                    └─────────┬───────┘
                              │
                    ┌─────────────────┐
                    │ Provisioning    │ ← Database Writer
                    │ Server          │   Manages User Provisioning
                    │ (Port 5001)     │   & Replica Synchronization
                    └─────────┬───────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
    ┌─────────────────┐ ┌─────────────────┐
    │ Primary KDC     │ │ Replica KDC     │
    │ (Port 8888)     │ │ (Port 8889)     │
    └─────────────────┘ └─────────────────┘
              │               │               │
              └───────────────┼───────────────┘
                              │
                    ┌─────────────────┐
                    │ Service Server  │ ← Protected Application
                    │ (Port 6001)     │   Validates Service Tickets
                    └─────────────────┘
```

### Core Problems Solved

| Traditional Kerberos Problem | Our Solution                     | Benefits                                                  |
| ---------------------------- | -------------------------------- | --------------------------------------------------------- |
| **Password Vulnerability**   | PKINIT with X.509 certificates   | Eliminates phishing, credential stuffing, offline attacks |
| **Single Point of Failure**  | Primary-Replica KDC architecture | 100% uptime, automatic failover                           |
| **Monolithic Architecture**  | Microservices with Docker        | Cloud-native, scalable, maintainable                      |
| **CLI-only Administration**  | RESTful APIs + React UI          | Modern UX, programmatic integration                       |

## Technology Stack

### Backend Services

- **Language**: Python 3.9+
- **Web Framework**: Flask (RESTful APIs)
- **Authentication Protocol**: WebSockets (KDC communication)
- **Cryptography**: `cryptography` library (RSA, AES-GCM, X.509, SHA-256)
- **Database**: SQLite (ACID-compliant, file-based)
- **Containerization**: Docker & Docker Compose

### Frontend Application

- **Framework**: React 18 with TypeScript
- **Styling**: Tailwind CSS
- **Routing**: React Router v6
- **Cryptography**: Web Crypto API (browser-native)
- **Certificate Handling**: PKI.js for X.509 operations
- **Build Tool**: Vite

### Infrastructure

- **Orchestration**: Docker Compose
- **Networking**: Private Docker bridge network (`kerberos-net`)
- **Storage**: Named Docker volumes for persistence
- **Health Checks**: Built-in container health monitoring

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Node.js 18+ (for frontend development)
- Git

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/kerberos.git
cd kerberos
```

### 2. Environment Setup

Create a `.env` file in the project root:

```bash
# Generate secrets with: openssl rand -base64 32
TGS_SECRET_KEY_B64=your_tgs_secret_key_base64
SERVICE_SECRET_KEY_B64=your_service_secret_key_base64
CA_PASSWORD=your_ca_password
INTERNAL_API_KEY=your_internal_api_key

# Optional configurations
REALM=MYKERBEROSPROJECT
TGT_LIFETIME_SECONDS=21600
SERVICE_TICKET_LIFETIME_SECONDS=300
TIMESTAMP_WINDOW_SECONDS=300
```

### 3. Launch the System

```bash
# Start all services
docker-compose up -d

# Verify all services are healthy
docker-compose ps
```

### 4. Access the Applications

- **React Frontend**: http://localhost:3000
- **CA Server API**: http://localhost:5000
- **Primary KDC**: WebSocket on localhost:8888
- **Replica KDC**: WebSocket on localhost:8889
- **Service Server**: WebSocket on localhost:6001

### 5. Test Authentication

#### Option A: Web Interface

1. Navigate to http://localhost:3000
2. Click "Sign Up" to create a new account
3. Generate keys and certificate in-browser
4. Login and access protected services

#### Option B: Python Client

```bash
# Run the integrated test client
docker exec -it ca_server python -m client.main
```

## 🔧 Service Components

### 1. Certificate Authority (CA) Server

**Port**: 5000 | **Role**: Identity Issuer

- Issues X.509 certificates for user authentication
- Manages Certificate Signing Requests (CSRs)
- Handles multi-device approval workflow
- Maintains certificate trust store

**Key Endpoints**:

- `GET /ca-cert` - Download CA public certificate
- `POST /submit-csr` - Submit certificate request
- `POST /poll-pending-requests` - Check for device approvals (authenticated)
- `POST /approve-request` - Approve/reject device requests (authenticated)

### 2. Key Distribution Centers (KDCs)

**Primary Port**: 8888 | **Replica Port**: 8889

**Primary KDC**:

- Initializes and manages the master authentication database
- Handles AS-REQ (Authentication Server requests)
- Processes TGS-REQ (Ticket Granting Server requests)
- Provides service discovery via LIST_SERVICES

**Replica KDC**:

- Read-only clone for high availability
- Automatic failover target
- Synchronized via Provisioning Server

**Protocol Support**:

- WebSocket-based communication
- AS-REQ: PKINIT authentication with certificate validation
- TGS-REQ: Service ticket generation
- LIST_SERVICES: Available service enumeration

### 3. Provisioning Server

**Port**: 5001 | **Role**: Database Writer & Replication Manager

- Only service with write access to KDC database
- Creates new user accounts and devices
- Synchronizes Primary → Replica database
- Protected by `INTERNAL_API_KEY`

**Key Endpoints**:

- `POST /provision-new-user` - Create new user account
- `POST /add-device` - Add device to existing user
- `POST /sync-replica` - Trigger manual database synchronization

### 4. Service Server

**Port**: 6001 | **Role**: Protected Application

- Validates Kerberos service tickets
- Demonstrates the AP-REQ protocol flow
- Returns protected data upon successful authentication
- Implements replay attack prevention

### 5. Frontend Application

**Port**: 3000 | **Role**: User Interface

- Browser-based key generation (WebCrypto API)
- Certificate request submission
- Multi-device approval interface
- Service access dashboard

## 🔐 Security Features

### Passwordless Authentication (PKINIT)

- **Private Key Generation**: 2048-bit RSA keys generated client-side
- **Certificate-based Authentication**: X.509 certificates replace passwords
- **Proof of Possession**: Digital signatures prove private key ownership
- **No Secrets in Database**: Only public key fingerprints stored

### Cryptographic Security

- **Encryption**: AES-256-GCM for symmetric encryption
- **Key Exchange**: RSA-OAEP for asymmetric encryption
- **Signatures**: RSA-PSS with SHA-256
- **Certificate Validation**: Full X.509 chain verification

### Anti-Replay Protection

- **Timestamp Windows**: 5-minute freshness requirement
- **Nonce Generation**: Cryptographically secure randomness
- **Session Keys**: Unique per authentication session
- **Ticket Expiration**: Configurable lifetime limits

### Network Security

- **Docker Network Isolation**: Private `kerberos-net` bridge
- **API Key Protection**: Internal service authentication
- **Certificate Pinning**: CA certificate validation
- **WebSocket Security**: Encrypted communication channels

## Authentication Flow

### Phase 1: AS-REQ (Authentication Server Request)

```
Client                           KDC
  |                               |
  | 1. Generate timestamp         |
  | 2. Sign {principal,timestamp} |
  |     with private key          |
  |                               |
  | AS-REQ{cert, principal,       |
  |        timestamp, signature}  |
  |------------------------------>|
  |                               | 3. Verify certificate chain
  |                               | 4. Validate signature
  |                               | 5. Check fingerprint in DB
  |                               | 6. Validate timestamp
  |                               | 7. Generate session key & TGT
  |                               |
  | {encrypted_session_key,       |
  |  encrypted_tgt}               |
  |<------------------------------|
```

### Phase 2: TGS-REQ (Ticket Granting Server Request)

```
Client                           KDC
  |                               |
  | 1. Create authenticator       |
  | 2. Encrypt with session key   |
  |                               |
  | TGS-REQ{tgt, authenticator,   |
  |         service_principal}    |
  |------------------------------>|
  |                               | 3. Decrypt TGT with TGS key
  |                               | 4. Decrypt authenticator
  |                               | 5. Validate timestamp & principal
  |                               | 6. Generate service ticket
  |                               |
  | {service_ticket,              |
  |  encrypted_service_session_key}|
  |<------------------------------|
```

### Phase 3: AP-REQ (Application Request)

```
Client                    Service Server
  |                            |
  | 1. Create authenticator    |
  | 2. Encrypt with service    |
  |    session key             |
  |                            |
  | AP-REQ{service_ticket,     |
  |        authenticator}      |
  |--------------------------->|
  |                            | 3. Decrypt ticket with service key
  |                            | 4. Decrypt authenticator
  |                            | 5. Validate timestamp & principal
  |                            |
  | Protected resource data    |
  |<---------------------------|
```

## Multi-Device Workflow

Our system implements a "zero-trust" multi-device approval process inspired by modern applications like Signal and WhatsApp.

### New Device Registration Flow

1. **Device Registration Request**

   ```bash
   # User attempts login from new device
   POST /submit-csr
   {
     "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----...",
     "is_signup": false
   }
   ```

2. **Pending Approval Response**

   ```json
   {
     "status": "pending_approval",
     "request_id": "uuid-string",
     "message": "Request received. Please approve from a trusted device."
   }
   ```

3. **Trusted Device Polling**

   ```bash
   # Existing device checks for pending requests
   POST /poll-pending-requests
   Headers: {
     "X-Client-Cert": "base64_certificate",
     "X-Client-Signature": "base64_signature",
     "X-Client-Timestamp": "ISO8601_timestamp"
   }
   ```

4. **Approval Decision**

   ```bash
   POST /approve-request
   {
     "request_id": "uuid-string",
     "action": "approve"  # or "reject"
   }
   ```

5. **New Device Polling**

   ```bash
   # New device polls for approval status
   GET /check-request-status/{request_id}
   ```

6. **Certificate Delivery**
   ```json
   {
     "status": "approved",
     "certificate": "-----BEGIN CERTIFICATE-----..."
   }
   ```

## Database Schema

### CA Database (`ca.db`)

```sql
-- Certificate issuance log
CREATE TABLE certificates (
    serial_number INTEGER PRIMARY KEY,
    subject_name TEXT NOT NULL,
    principal_name TEXT NOT NULL,
    status TEXT NOT NULL,  -- 'trusted', 'pending', 'revoked'
    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE
);

-- Multi-device approval queue
CREATE TABLE pending_requests (
    request_id TEXT PRIMARY KEY,
    principal_name TEXT NOT NULL,
    new_csr_pem TEXT NOT NULL,
    new_cert_subject TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### KDC Database (`kdc.db`)

```sql
-- Master user accounts
CREATE TABLE users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    principal_name TEXT NOT NULL UNIQUE
);

-- Trusted devices per user
CREATE TABLE devices (
    device_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    cert_fingerprint TEXT NOT NULL UNIQUE,
    cert_subject TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'trusted',
    FOREIGN KEY (user_id) REFERENCES users (user_id)
);

-- Service cryptographic keys
CREATE TABLE service_keys (
    principal_name TEXT PRIMARY KEY NOT NULL,
    secret_key_b64 TEXT NOT NULL
);

-- Service metadata
CREATE TABLE services (
    service_id INTEGER PRIMARY KEY AUTOINCREMENT,
    principal_name TEXT UNIQUE NOT NULL,
    service_name TEXT NOT NULL,
    service_url TEXT,
    description TEXT,
    FOREIGN KEY (principal_name) REFERENCES service_keys (principal_name)
);
```

## Configuration

### Environment Variables

| Variable                          | Description                            | Required | Default             |
| --------------------------------- | -------------------------------------- | -------- | ------------------- |
| `TGS_SECRET_KEY_B64`              | TGS service encryption key (base64)    | ✅       | -                   |
| `SERVICE_SECRET_KEY_B64`          | Service server encryption key (base64) | ✅       | -                   |
| `CA_PASSWORD`                     | CA private key password                | ✅       | -                   |
| `INTERNAL_API_KEY`                | Inter-service authentication key       | ✅       | -                   |
| `REALM`                           | Kerberos realm name                    | ❌       | `MYKERBEROSPROJECT` |
| `TGT_LIFETIME_SECONDS`            | Ticket-Granting Ticket lifetime        | ❌       | `21600` (6 hours)   |
| `SERVICE_TICKET_LIFETIME_SECONDS` | Service ticket lifetime                | ❌       | `300` (5 minutes)   |
| `TIMESTAMP_WINDOW_SECONDS`        | Replay attack prevention window        | ❌       | `300` (5 minutes)   |

### Frontend Configuration

Create `frontend/.env`:

```bash
VITE_CA_URL=http://localhost:5000
VITE_KDC_PRIMARY_URL=ws://localhost:8888
VITE_KDC_REPLICA_URL=ws://localhost:8889
VITE_SERVICE_URL=ws://localhost:6001
```

### Docker Compose Override

For production deployment, create `docker-compose.override.yml`:

```yaml
version: "3.8"
services:
  ca-server:
    environment:
      - FLASK_ENV=production
    restart: unless-stopped

  primary-kdc:
    deploy:
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M
```

## Development Guide

### Local Development Setup

1. **Backend Development**

   ```bash
   # Install Python dependencies
   pip install -r requirements.txt

   # Run individual services
   python -m ca_server.main
   python -m kdc_server.main --role primary
   python -m provisioning_server.main
   python -m service_server.main
   ```

2. **Frontend Development**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

### Debugging

1. **View Logs**

   ```bash
   # All services
   docker-compose logs -f

   # Specific service
   docker-compose logs -f ca-server
   ```

2. **Database Inspection**

   ```bash
   # Connect to CA database
   docker exec -it ca_server sqlite3 /app/data/ca.db

   # Connect to KDC database
   docker exec -it primary_kdc sqlite3 /app/db/primary/kdc.db
   ```

3. **Network Testing**
   ```bash
   # Test WebSocket connections
   websocat ws://localhost:8888
   {"type": "health_check"}
   ```

## API Documentation

### CA Server REST API

#### Get CA Certificate

```http
GET /ca-cert
Accept: application/x-pem-file
```

#### Submit Certificate Request

```http
POST /submit-csr
Content-Type: application/json

{
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----...",
  "is_signup": true
}
```

#### Poll for Pending Requests (Authenticated)

```http
POST /poll-pending-requests
X-Client-Cert: base64_encoded_certificate
X-Client-Signature: base64_encoded_signature
X-Client-Timestamp: 2024-01-01T12:00:00Z
```

### KDC WebSocket API

#### Authentication Server Request

```json
{
  "type": "AS_REQ",
  "cert_pem": "-----BEGIN CERTIFICATE-----...",
  "principal": "user@REALM",
  "timestamp": "2024-01-01T12:00:00Z",
  "signed_data": "base64_signature"
}
```

#### Ticket Granting Server Request

```json
{
  "type": "TGS_REQ",
  "tgt": "base64_encrypted_tgt",
  "authenticator": "base64_encrypted_authenticator",
  "service_principal": "host/service.server@REALM"
}
```

#### List Available Services

```json
{
  "type": "LIST_SERVICES"
}
```

### Service Server WebSocket API

#### Application Request

```json
{
  "type": "AP_REQ",
  "service_ticket": "base64_encrypted_ticket",
  "authenticator": "base64_encrypted_authenticator"
}
```

## Troubleshooting

### Common Issues

#### 1. Certificate Validation Errors

```bash
# Symptom: "Certificate signature is invalid"
# Solution: Verify CA certificate is properly loaded
docker exec -it primary_kdc ls -la /app/data/ca_cert.pem
```

#### 2. Database Connection Issues

```bash
# Symptom: "Database file not found"
# Solution: Check volume mounts and initialization
docker-compose exec primary-kdc ls -la /app/db/primary/
```

#### 3. WebSocket Connection Failures

```bash
# Symptom: Connection refused on KDC ports
# Solution: Check service health and port mapping
docker-compose ps
curl -f http://localhost:8888 || echo "KDC not responding"
```

#### 4. Frontend Key Generation Issues

```bash
# Symptom: "WebCrypto not available"
# Solution: Ensure HTTPS or localhost context
# Check browser console for detailed errors
```

### Health Checks

All services include built-in health checks:

```bash
# Check overall system health
docker-compose ps

# Individual service health
docker exec ca_server python -c "import requests; print(requests.get('http://localhost:5000/ca-cert').status_code)"
```

### Performance Monitoring

```bash
# Resource usage
docker stats

# Database performance
docker exec primary_kdc sqlite3 /app/db/primary/kdc.db ".timer on" ".stats on" "SELECT COUNT(*) FROM users;"
```

## 🤝 Contributing

### Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Submit a Pull Request

### Code Standards

- **Python**: Follow PEP 8, use type hints
- **TypeScript**: Follow ESLint configuration
- **Docker**: Multi-stage builds, minimal base images
- **Documentation**: Update README for new features

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙋‍♀️ Support

- **Documentation**: Check this README and inline code comments
- **Issues**: Report bugs via GitHub Issues
- **Discussions**: Join our GitHub Discussions for questions

## 🔮 Future Roadmap

- [ ] Hardware Security Module (HSM) integration
- [ ] Certificate Revocation List (CRL) support
- [ ] OAuth 2.0 / OpenID Connect integration
- [ ] Kubernetes deployment manifests
- [ ] WebAuthn compatibility layer
- [ ] Mobile application (React Native)
- [ ] Metrics and monitoring (Prometheus/Grafana)
- [ ] Audit logging and compliance reporting

---

**Built with ❤️ by the Modern Kerberos Team**

_Revolutionizing authentication, one certificate at a time._
