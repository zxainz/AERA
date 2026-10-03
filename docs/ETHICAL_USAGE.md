# Ethical Usage Policy

AERA (Autonomous Exploit Research Assistant) exists for **authorized defensive
security research only**. If you cannot meet every condition below, do not use it.

## You must

1. **Have explicit written authorization** to test every system you analyze or
   validate against. "Probably fine" is not authorization.
2. **Stay in the sandbox.** All PoC execution happens in isolated Docker
   containers with no network access. Do not copy generated PoCs onto live
   targets.
3. **Follow responsible disclosure** for any new vulnerability you confirm:
   notify the vendor/owner first, respect their timeline.
4. **Comply with the law** in your jurisdiction (e.g. CFAA, UK Computer Misuse
   Act, EU national implementations, Pakistan's PECA 2016 where applicable).
5. **Keep audit logs.** AERA logs every run; do not delete or tamper with them.
   They are your evidence of authorized conduct.

## You must never

- Test systems you do not own or have written permission to test.
- Weaponize output: no persistence, no lateral movement, no obfuscation,
  no packaging PoCs for delivery.
- Scan or probe third-party networks, even "just to check".
- Remove or weaken the authorization gate, sandbox isolation, or audit logging.

## Design limits (intentional)

- No network scanning capabilities.
- No live-target execution path: the sandbox enforces `network_mode="none"`.
- Authorization tokens are short-lived, narrow-scope, and domain-bound.
- PoC output is educational/validation-grade, clearly commented, with no
  anti-analysis techniques.

Violating this policy may be a criminal offence. The authors provide this tool
for research and education and accept no liability for misuse.
