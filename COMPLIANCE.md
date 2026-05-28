# RealAgentID — Compliance Framework

*This document maps RealAgentID's architecture to relevant compliance
frameworks. It is a living document updated as the project evolves.*

---

## Design Principles

RealAgentID is built compliance-first. Every architectural decision
considers regulatory requirements before implementation, not after.

Core principles:
- Minimum necessary data — metadata only, never payload content by default
- Separation of duties — log generators cannot modify audit trails
- Tamper evidence — cryptographic chaining of audit entries (roadmap)
- Configurable retention — deployments set their own policies
- On-prem first — data residency is always the operator's choice

---

## Framework Mappings

### SOC 2 — Trust Service Criteria

| Criteria | RealAgentID Control | Status |
|---|---|---|
| Security | Agent identity verification, message signing | ✅ v0.1 |
| Availability | Proxy uptime monitoring | 📋 Roadmap |
| Processing Integrity | Tamper detection and rejection | ✅ v0.1 |
| Confidentiality | Payload sanitization, access controls | 🔨 v0.2 |
| Privacy | Retention policies, right to erasure | 📋 Roadmap |

---

### GDPR

| Principle | RealAgentID Approach | Status |
|---|---|---|
| Data minimization | Metadata logged only by default | ✅ v0.1 |
| Purpose limitation | Audit logs for security use only | ✅ v0.1 |
| Storage limitation | Configurable retention periods | 📋 Roadmap |
| Integrity & confidentiality | Tamper-evident audit trail | 🔨 v0.2 |
| Right to erasure | Identity purge process | 📋 Roadmap |

---

### HIPAA

| Requirement | RealAgentID Approach | Status |
|---|---|---|
| PHI protection | Payload never logged by default | ✅ v0.1 |
| Audit controls | Structured timestamped event log | ✅ v0.1 |
| Integrity controls | Tamper detection | ✅ v0.1 |
| Access controls | IAM on audit trail | 🔨 v0.2 |

---

### NIST AI RMF

| Function | RealAgentID Mapping | Status |
|---|---|---|
| Govern | Agent authorization policy framework | 🔨 v0.2 |
| Map | Agent identity registry | ✅ v0.1 |
| Measure | Audit log with verification metrics | ✅ v0.1 |
| Manage | Tamper detection and rejection | ✅ v0.1 |

## POST-QUANTUM-Cryptography Compliance

### NIST FIPS 204 (ML-DSA)

| Agent identity signatures use ML-DSA-65 |
| Equivalent to AES-192 / 3072-bit RSA classical security |
| Quantum-resistant against Shor's algorithm attacks |

### NIST FIPS 203 (ML-DSA / Kyber)

| Vault key encapsulation uses Kyber512 |
| Protects agent session keys against harvest-now-decrypt-later attacks |

### Implementation

| Liboqs (Open Quantum Safe) v0.15.0 |
| Python wrapper: liboqs-python v0.16.0 |
| Graceful fallback to classical encryption if liboqs unavailable |
---

### EU AI Act

| Requirement | RealAgentID Approach | Status |
|---|---|---|
| Logging & traceability | Structured audit trail | ✅ v0.1 |
| Human oversight | Audit log human-readable by design | ✅ v0.1 |
| Transparency | Open source, auditable codebase | ✅ v0.1 |
| Accuracy & robustness | Cryptographic verification | ✅ v0.1 |

---

## Responsibility Boundary

RealAgentID provides the tools. Compliance is a shared responsibility.

**RealAgentID is responsible for:**
- Providing compliant-ready tooling and architecture
- Logging metadata accurately and tamper-evidently
- Documenting compliance mappings and design decisions
- Maintaining open source auditability

**The deploying organization is responsible for:**
- Configuring retention periods per their requirements
- Securing infrastructure RealAgentID runs on
- Integrating audit logs into their SIEM
- Obtaining their own compliance certifications

---

## Roadmap

- v0.2 — Payload sanitization controls, Redis Streams backend,
  audit log access controls
- v0.3 — Tamper-evident log chaining, configurable retention,
  pluggable SIEM destinations
- v0.4 — Right to erasure, identity purge process,
  FedRAMP alignment documentation

---

*Apache 2.0 — open source, always.*
*RealAgentID is not a law firm and this is not legal advice.*
*Consult qualified compliance counsel for your specific requirements.*

---

### NIST AI RMF Mapping

| Function | AI RMF Function | Subcategory |
|---|---|---|
| keygen.py + registry.py | GOVERN | GV-1.1 - AI risk policies established |
| signing.py | MAP | MP-2.3 - AI system trustworthiness evaluated |
| verify_message_from_registry() | MEASURE | MS-2.5 - AI system identity verified |
| audit.py | MANAGE | MG-2.2 - Incident response logs maintained |
| tamper_test.py | MEASURE | MS-1.1 - AI risk evaluated and tested |

---

### EU AI Act Mapping

| RealAgentID Control | EU AI Act Requirement | Article |
|---|---|---|
| Agent identity verification | Traceability of AI system actions | Art. 12 |
| Audit logging via audit.py | Record-keeping for high-risk AI | Art. 12 |
| Tamper detection | Robustness and cybersecurity | Art. 15 |
| Registry-based trust | Human oversight enablement | Art. 14 |
| TTL enforcement | Accuracy and reliability controls | Art. 15 |

---

### HIPAA Mapping

| RealAgentID Control | HIPAA Safeguard | Rule |
|---|---|---|
| Agent identity via keygen.py | Unique user identification | 164.312(a)(2)(i) |
| Registry verification | Person or entity authentication | 164.312(d) |
| Audit logging via audit.py | Audit controls | 164.312(b) |
| Message signing | Transmission integrity | 164.312(e)(2)(i) |
| TTL enforcement | Automatic logoff equivalent | 164.312(a)(2)(iii) |
