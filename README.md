# MinLish Android AppSec — Security Assessment Portfolio

A focused security assessment of an existing Kotlin/Firebase Android application using static analysis, controlled dynamic testing, Frida instrumentation, isolated Firebase authorization experiments, and Python/SQLite security-log analysis.

The Android application is attributed to [dangpham258/MinLish-AndroidApp](https://github.com/dangpham258/MinLish-AndroidApp). My contribution is the AppSec analysis, targeted logging remediation, lab/evidence work, Debug diagnostics, analyzer and reporting; I do not claim authorship of the complete application.

## Start here

- **[Read the Quick Overview](mentor-quick-review-v1/START-HERE.md)**
- **[Read the Security Report — PDF](mentor-quick-review-v1/SECURITY-REPORT.pdf)** — four pages; [Markdown version](mentor-quick-review-v1/SECURITY-REPORT.md) available.
- **[View Supporting Evidence](mentor-quick-review-v1/evidence/)** — four representative, scope-limited artifacts.

## Security assessment summary

- **T-01 — Sensitive Deep-Link Logging:** synthetic logging is confirmed on the tested path. Both targeted source sinks use the URI-omitted message; historical filtered MinLishApp retest support exists. Runtime NavGraph remediation remains NOT VERIFIED; no application-wide logging clearance is claimed.
- **T-02 — Firebase Realtime Database Authorization:** isolated local lab observations and partial authorization verification. Console simulation, administrator fixture controls and local tests are distinguished. No unauthorized production access or production deployment is claimed.
- **T-03 — Client-Side Authentication State Manipulation:** historical Frida work is partially independently verified. The complete mutation/UI/Firebase-session chain lacks retained artifacts; Firebase signed-out state and the decks-denial claim remain REPORT ONLY. No Firebase Authentication or backend authorization bypass is claimed.

## Additional engineering

- Debug-only Root and Frida instrumentation diagnostics: archived 10/11 detector unit-test results and structured runtime events.
- Python + SQLite Security Log Analyzer: standard-library validation, duplicate handling and CSV export; the private handoff verified seven tests and a four-event mixed-state sample.

These are supporting contributions, not additional findings or evidence of attack prevention. Full analyzer code/tests and extension documentation remain in the separate technical appendix; this change adds only the Quick Review and this README.

## Methodology

Static Analysis → Dynamic Validation → Evidence Collection → Remediation → Retesting → Reporting.

Each outcome is labeled by its actual evidence. Some runtime demonstrations are historical or partially verified; the workflow is not a claim that every test or remediation passed.

## Scope and limitations

This is a focused AppSec learning project, not a comprehensive penetration test. Local Firebase Emulator results are not production exploitation evidence. Root/Frida detection is bypassable telemetry, not guaranteed prevention or backend authorization. Source ownership, distribution rights and evidence privacy must be preserved; no Android source/APK is added by this change.

## Technical documentation

The [historical detailed assessment](report/security-assessment.md), [Firebase lab files](firebase-lab/) and [Frida setup notes](frida-server/README.md) are retained. Use the Quick Review for current evidence-scoped conclusions: older technical records can contain broader claims that the short report qualifies. Retaining those files is not a new privacy/license clearance.
