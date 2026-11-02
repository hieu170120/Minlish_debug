# MinLish AppSec v1.0 - Start here

## Project and contribution

A small Android AppSec portfolio assessing an existing learning app (com.minlish.app). Personal work covers focused analysis, targeted logging remediation, local authorization-lab evidence, Frida research, Debug diagnostics and a Python/SQL analyzer. The upstream app is attributed to [dangpham258/MinLish-AndroidApp](https://github.com/dangpham258/MinLish-AndroidApp); authorship of the whole application is not claimed.

## Read in this order

1. Read [SECURITY-REPORT.pdf](SECURITY-REPORT.pdf) (four pages), or the identical-content [Markdown report](SECURITY-REPORT.md).

2. Open evidence E01-E04 only when a finding refers to it. No appendix reading is required.

## Main results

T-01: synthetic before/after logs; two sinks statically checked. Runtime NavGraph remains NOT VERIFIED.

T-02: selected local authorization outcomes are visible; overall lab coverage remains PARTIAL. No unauthorized production access is demonstrated.

T-03: enumeration/script image exists; complete hooking/UI/Firebase-session chain is not independently retained. No Firebase Authentication or backend authorization bypass is demonstrated.

## Optional technical appendix - not copied here

The original 71-file Minlish-debug-mentor-review-v1 bundle remains separate. Open its START-HERE.md for the full assessment and index. Its evidence/p0-04/authorization-matrix.md contains the matrix; log-analyzer/ holds code/tests/sample; extensions/ contains detector reports/results. The eight held images are NOT INCLUDED there or here.

## Scope of this package

Private mentor feedback only. No Android source/APK, credentials, new tests, security features or deployment. Four representative evidence files accompany this short report; full runtime/build proof remains incomplete. Checksums are supplied for integrity.

