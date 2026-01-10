# 🩸 BloodTrailCLI

**BloodTrailCLI** is a lightweight, menu-driven command-line tool for parsing and mapping Active Directory relationships from **SharpHound** data — without requiring Neo4j or the BloodHound UI.

It is designed for **red teamers, blue teamers, and lab environments** where quick visibility into impactful AD relationships (ACLs, delegation, GPO links, etc.) is needed directly from the CLI.

*Possible future updates: adding comptabiltiy with more collectors. Support for containers.
---

## 🚀 Features

- ✅ Parses SharpHound ZIP collections
- ✅ Maps critical Active Directory relationships:
  - ACLs / ACEs (GenericWrite, GenericAll, Owns, etc.)
  - Group membership
  - Delegation
  - GPO → OU / Domain links
  - Domain trust relationships
- ✅ Resolves **SIDs → readable object names** when possible
- ✅ Clean menu-driven CLI (no silent exits)
- ✅ UTF-8 BOM–safe parsing (Windows SharpHound friendly)
- ✅ No external dependencies (Python standard library only)

---
## 🧠 Example Output

```bash
READ-ONLY DOMAIN CONTROLLERS@TECH.CORP     -- MemberOf             --> DENIED RODC PASSWORD REPLICATION GROUP@TECH.CORP
GROUP POLICY CREATOR OWNERS@TECH.CORP      -- MemberOf             --> DENIED RODC PASSWORD REPLICATION GROUP@TECH.CORP
DOMAIN ADMINS@TECH.CORP                    -- MemberOf             --> DENIED RODC PASSWORD REPLICATION GROUP@TECH.CORP
CERT PUBLISHERS@TECH.CORP                  -- MemberOf             --> DENIED RODC PASSWORD REPLICATION GROUP@TECH.CORP
ENTERPRISE ADMINS@TECH.CORP                -- MemberOf             --> DENIED RODC PASSWORD REPLICATION GROUP@TECH.CORP
SCHEMA ADMINS@TECH.CORP                    -- MemberOf             --> DENIED RODC PASSWORD REPLICATION GROUP@TECH.CORP

## 📦 Supported SharpHound Files

BloodTrailCLI currently supports the following SharpHound JSON files:

| File | Parsed Relationships |
|----|----|
| `computers.json` | ACLs / ACEs |
| `groups.json` | Group membership |
| `users.json` | Delegation |
| `gpos.json` | GPO links |
| `domains.json` | Domain trusts |
| `ous.json` | OU structure |

Other files (e.g. `containers.json`) are silently skipped.

---

## 🔧 Requirements

- Python **3.6+**
- SharpHound data (`.zip` output)

No third-party Python libraries are required.

---

## 🛠️ Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/BloodTrailCLI.git
cd BloodTrailCLI
