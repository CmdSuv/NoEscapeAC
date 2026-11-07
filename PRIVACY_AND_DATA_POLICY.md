# NoEscapeAC — Privacy & Data Protection Policy

**Version:** 7.0 / Release 1.3  
**Status:** Official Privacy Standard  
**Attribution:** Omar Yiğitcan Mengü (`@CmdSuv`) & `OnlyCosmos` (`@OnlyCosmos`)

---

## 1. Core Privacy Commitments

NoEscapeAC is designed as a focused, privacy-respecting client integrity engine. The anti-cheat strictly adheres to the principle of **data minimization** and **Zero Personally Identifiable Information (Zero PII)** collection:
1. **No Personal Data Harvesting:** NoEscapeAC does not inspect, read, or transmit player personal files, documents, photos, browser histories, saved passwords, or private communications.
2. **Confined Process Scope:** Memory scanning and unhooking operations are strictly restricted to the address space of the game process and loaded system dynamic libraries.
3. **No Keylogging:** Kinematic mouse input analysis monitors purely relative angular displacement vectors $(\Delta x, \Delta y)$ and timestamps within the game window. It does not record keystrokes or arbitrary desktop input.
4. **No Desktop Screen Scraping:** Overlay detection inspects window class names and z-order hierarchies. It never captures, screenshots, or transmits desktop screen contents.

---

## 2. Hardware ID (HWID) Fingerprinting

To uniquely enforce bans against bad actors while protecting physical hardware confidentiality:
- Hardware ID generation uses HMAC-SHA256 across combined machine identifiers (CPU feature flags, system product UUID, and MAC address hash).
- The raw hardware serial numbers are never transmitted in plaintext.
- The resulting 256-bit hexadecimal digest is an irreversible one-way cryptographic hash that cannot be inverted to reconstruct the user's physical components.

---

## 3. Blackbox Diagnostic Crash & Violation Dumps

When a critical anti-cheat violation or crash occurs:
- The engine generates an encrypted diagnostic dump file (`/tmp/noescape_blackbox_*.dmp`).
- The payload is encrypted using **AES-256-GCM** with an ephemeral deployment key.
- Dumps contain only technical telemetry:
  - Offending virtual memory page protections and relative instruction offsets.
  - Timestamp, detection category, and threat score delta.
  - Anti-cheat engine internal execution logs.
- Dumps contain zero user files or personal data and are automatically deleted upon resolution.

---

## 4. Network Telemetry Minimization

All communication between the game client and the backend panel utilizes TLS 1.2+ encrypted channels with HMAC-SHA256 request signatures:
- Packets transmit strictly structured telemetry: `DetectionType`, `Severity`, `Timestamp`, `ThreatScore`, and `HwidFingerprint`.
- No raw memory dumps or binary images are transmitted across the network unless explicitly requested by the game operator via a signed administrative challenge.
