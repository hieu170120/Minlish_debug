# Android APK Security Lab — MinLish (com.minlish.app)

## Overview
This project is a controlled Android application penetration testing and security assessment lab built to evaluate and improve mobile security posture. The target application is **MinLish** (`com.minlish.app`), an Android English vocabulary learning application backed by Firebase.

The lab covers the full workflow of a professional mobile app assessment: environment setup, static analysis via reverse engineering, vulnerability identification, dynamic validation and runtime instrumentation on a live emulator, backend authorization analysis in an isolated Firebase Emulator, remediation implementation, and verification retesting.

## Objective
Build a controlled, self-contained Android pentesting and security assessment lab to identify, validate, and remediate real vulnerability classes commonly found in Android and cloud-integrated mobile applications:
- **Sensitive Data Exposure Through Logging** (CWE-532) via static code analysis and dynamic Logcat inspection.
- **Improper Access Control / Insecure Cloud Database Rules** (CWE-284) via Firebase Console audit, Rules Playground simulation, and local Firebase Emulator authorization testing with synthetic fixtures.
- **Client-Side Authentication State Manipulation & Navigation Bypass** (CWE-602) via dynamic instrumentation with Frida, heap object enumeration, Java reflection, and backend session verification.

## Lab Environment

| Item | Details |
|---|---|
| **Operating System** | Windows 11 Home Single Language, Build 26200, x64 |
| **Laptop** | Lenovo, Model 82QD |
| **CPU** | 12th Gen Intel(R) Core(TM) i5-1235U |
| **RAM** | ~7.73 GB |
| **Target Application** | MinLish (`com.minlish.app`), Debug & Release builds |
| **Emulator Environment** | Android Virtual Device (`emulator-5554`, API 28 / x86_64) |
| **Tools Used** | • **Android Platform Tools (ADB & Logcat)** — device/emulator communication, intent launching, and log monitoring<br>• **JADX GUI** — APK decompilation, bytecode reverse engineering, and static source review<br>• **Frida CLI (v17.19.0)** & `frida-server` — dynamic runtime instrumentation, heap inspection, and Java reflection<br>• **Firebase Suite (CLI, Realtime Database & Auth Emulator, `@firebase/rules-unit-testing`)** — local, isolated backend authorization testing<br>• **Gradle** — APK build automation (`:app:assembleDebug`, `:app:assembleRelease`) |

## Methodology

- **Static Analysis** — Decompiled the MinLish APK using JADX and manually reviewed source code for common Android vulnerability patterns:
  - Deep-link URI processing in `MainActivity.handleDeepLink()` and destination routing in `NavGraphKt`.
  - Database access paths in `FirebaseDatabaseService` (`/users/{uid}`, `/decks`, `/vocabularyStates`, `/reviewHistories`).
  - Observable authentication state flows in `AuthViewModel` (`_isUserLoggedIn: MutableStateFlow<Boolean?>`).
- **Dynamic Analysis & Runtime Instrumentation** — Tested MinLish on an Android Virtual Device (AVD) using ADB and Frida:
  - Triggered synthetic password-reset intents (`minlish://reset_password/FAKE_TEST_CODE_001`) to reproduce deep-link logging in Logcat.
  - Attached Frida to the running application process, enumerated active heap instances of `AuthViewModel`, and modified the private `_isUserLoggedIn` field via Java reflection, demonstrating a client-side navigation bypass from Login to Deck view.
  - Queried `FirebaseAuth.getCurrentUser()` at runtime to confirm that client-side navigation manipulation did not forge a valid Firebase session, and observed backend denial in Logcat (`Error fetching decks: Permission denied`).
- **Backend Authorization & Security Rules Testing** — Evaluated Firebase Realtime Database rules:
  - Audited deployed console rules and verified expiration of time-based root access (`now < 1782320400000`).
  - Configured an isolated local Firebase Emulator (`demo-minlish-security-lab`) with synthetic User A and User B fixtures.
  - Reproduced unauthorized public-read behavior under permissive rules, implemented owner-scoped UID rules (`auth.uid === $uid`), and validated positive/negative access control across unauthenticated, own-user, and cross-user operations.
- **Remediation & Regression Retesting** — Implemented code fixes:
  - Replaced full-URI logging in `MainActivity` with safe, non-sensitive event messages; verified the fix on rebuilt Debug APK via ADB and on Release APK via JADX static inspection.
  - Designed and verified UID-scoped access rules for Firebase Realtime Database.

## Findings Summary

| # | Finding | Type | Status |
|---|---|---|---|
| **1** | Sensitive Data Exposure Through Deep-Link Logging (T-01) | Insecure Logging (CWE-532) | Statically identified, dynamically validated on Debug APK, and remediated (verified via Debug retest & Release APK static check) |
| **2** | Time-Based Root-Level Firebase Access Without User Authorization (T-02) | Improper Access Control (CWE-284) | Statically identified, evaluated in Firebase Console, reproduced & remediated with UID-scoped rules in isolated Firebase Emulator |
| **3** | Client-Side Authentication State Manipulation & Navigation Bypass (T-03) | Client-Side Trust (CWE-602) | Dynamically validated via Frida runtime instrumentation; client navigation bypassed while backend data access denied |

Full details, code excerpts, evidence, and remediation guidance are in [report/security-assessment.md](report/security-assessment.md).

---

## Repository Structure

```text
.
├── evidence/
│   ├── T01-sensitive-logging/                 # Screenshots & Logcat outputs before/after fix
│   ├── T02-firebase-access-control/           # Firebase console & emulator test evidence
│   └── T03-Firebase Authorization Retesting/  # Frida instrumentation & authorization evidence
├── firebase-lab/                              # Local isolated Firebase security lab
│   ├── database.rules.json                    # Locally remediated UID-scoped rules
│   ├── database.rules.baseline.json           # Baseline default-deny rules
│   ├── database.rules.insecure.json           # Permissive reproduction rules
│   ├── test-authorization.cjs                 # Authorization matrix test script
│   └── seed-users.json                        # Synthetic test user fixtures
├── frida-server/                              # Frida server setup guide
│   └── README.md
├── report/
│   └── security-assessment.md                 # Full detailed security assessment report
├── .gitignore
└── README.md
```
