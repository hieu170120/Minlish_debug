# MinLish Android Security Assessment

**Assessment type:** Android APK static analysis, dynamic instrumentation, authorization testing, and remediation verification  
**Application:** MinLish (`com.minlish.app`)  
**Assessment period:** 28–29 October 2026  
**Report status:** T-01 remediated for the tested logging path; T-02 authorization rules remediated and retested in an isolated Firebase Emulator only; T-03 client-side navigation bypass reproduced with Frida, with backend authorization bypass **not demonstrated**. No production Firebase remediation or runtime retest of the patched Release APK has been demonstrated.

---

## 1. Executive Summary

A focused security assessment was conducted on MinLish (`com.minlish.app`) across three test areas: Android password-reset deep-link logging, Firebase Realtime Database access control, and client-side authentication-state manipulation. APK static analysis, Android emulator reproduction, Frida runtime instrumentation, Firebase Console rule simulation, and isolated Firebase Emulator authorization tests were used to distinguish observed behavior from potential impact.

**T-01 — Sensitive deep-link logging.** JADX inspection identified full-URI logging in `MainActivity.handleDeepLink()`, and a Debug APK test reproduced it with a synthetic reset code. The logging statement was replaced with a non-sensitive message; Debug runtime retesting passed, and JADX inspection confirmed the patched statement in the rebuilt Release APK. No patched Release APK runtime test or unauthorized log access was demonstrated.

**T-02 — Time-based Firebase rules without ownership checks.** Rules viewed in the MinLish Firebase Console used root-level read/write conditions based only on a timestamp. Before **25 June 2026, 00:00 (UTC+07:00)**, those conditions would have allowed ordinary clients to read and write without checking authentication or record ownership. By the assessment date, the timestamp had expired; Rules Playground simulations showed requests being **denied**, including authenticated requests. This is not evidence of a currently exploitable open database. An isolated Firebase Realtime Database Emulator reproduced public-read exposure under intentionally permissive local rules, then demonstrated UID-based isolation under locally remediated rules. The owner-read and cross-user read tests were directly evidenced by command output; subsequent cross-user write and own-user write test success was confirmed by the assessor but raw terminal outputs were not supplied with this report.

**T-03 — Client-side authentication-state manipulation.** Frida was attached to the running MinLish Android process. A JavaScript script located two `AuthViewModel` instances and used Java reflection to set each private `_isUserLoggedIn` `MutableStateFlow` to `true`. The tester observed navigation from the Login screen to the Deck screen. A separate Frida verification script showed `FirebaseAuth.getCurrentUser()` was `null` (`SIGNED OUT`), and application Logcat recorded `Error fetching decks: Permission denied`. Thus **client-side navigation bypass was demonstrated; Firebase authentication bypass and unauthorized backend data access were not**. Separate Firebase Authentication/Realtime Database Emulator tests showed UID-scoped rules denying unauthenticated and cross-user access while allowing same-user access. These local tests are **not evidence of production Firebase configuration**. Full scripts and evidence limitations are provided in §3.23–3.35.

**Summary of findings**

| ID | Finding | Classification | Severity | Status |
|---|---|---|---|---|
| T-01 | Potential sensitive-data exposure through deep-link logging | CWE-532 | Low (provisional) | Remediated in tested path; Debug retest PASS; Release static check PASS |
| T-02 | Time-based root-level Firebase access without user-level authorization | CWE-284 | Provisional — potentially high historical impact; not impact-confirmed | Local rules remediation and Emulator retests PASS (partly user-confirmed); production rules unchanged in this assessment |
| T-03 | Runtime manipulation of authentication state permits Login → Deck navigation | Client-side trust / potential CWE-602 mapping | **Low (provisional)** | UI navigation bypass CONFIRMED; Firebase session signed out; `/decks` read DENIED; local UID-rule tests PASS; no production backend bypass demonstrated |

**Key limitation:** No genuine password-reset code, third-party log access, historical Firebase data extraction, unauthorized production database access, Firebase session forgery, cross-account access on the live service, or production Firebase rule deployment was demonstrated. Frida-based UI navigation bypass must **not** be described as Firebase Authentication bypass. Local Emulator behavior must **not** be described as a production exploit.

## 2. Scope & Methodology

### 2.1 Scope

**In scope — T-01**

- The MinLish Android application and password-reset deep-link handling.
- `MainActivity.handleDeepLink()` and related navigation in `NavGraphKt` and `Screen.ResetPassword`.
- Password-reset code handling identified in `AuthRepositoryImpl`.
- Locally built Debug and Release APKs; ADB/Logcat reproduction and patch verification.

**In scope — T-02**

- Static review of Firebase database access paths in `FirebaseDatabaseService`.
- Inspection of `firebase.json` and availability of its referenced `database.rules.json`.
- Firebase Console Security Rules and read/write Rules Playground simulations.
- An isolated local Firebase Realtime Database Emulator using project ID `demo-minlish-security-lab`, with synthetic User A/User B data.
- Baseline, deliberately permissive, and locally remediated authorization tests for `/users/{uid}`.

**In scope — T-03**

- Static inspection of `AuthViewModel`, `NavGraph.kt`, `DeckViewModel`, `BunnyRepositoryImpl`, and relevant `FirebaseDatabaseService` methods.
- Frida runtime instrumentation of the running Android application, including authentication-state manipulation and independent Firebase-session inspection.
- Observed Login → Deck navigation and Logcat evidence for the signed-out `/decks` request.
- Separate local Firebase Authentication + Realtime Database Emulator testing of synthetic identities for `/vocabularyStates/{uid}` and unauthenticated `/reviewHistories/guest_user` access; verification of the effective rules in the correct database namespace.

**Out of scope / not established**

- Real Firebase password-reset codes or account takeover.
- Unauthorized reading of another application's Android logs or production logging infrastructure.
- Dynamic execution of the patched Release APK.
- Exploitation or historical access of MinLish's production Firebase database.
- Production deployment of new Firebase Security Rules or end-to-end production functional retesting.
- Comprehensive production authorization testing of `/decks`, `/deck_vocabularies`, `/vocabularyStates`, `/reviewHistories`, other Firebase services, or Firebase Functions. T-03 includes **limited, synthetic local Emulator** checks for two of those paths and one observed signed-out `/decks` denial; that is not full live-service coverage.
- Verified exposure of sensitive local Deck data or privileged operations after the navigation bypass.
- A complete application penetration test.

### 2.2 Environment and tools

| Item | Details |
|---|---|
| Target package | `com.minlish.app` |
| Android environment | Android emulator (`emulator-5554`); JADX GUI; ADB; Logcat |
| Build process | Gradle `:app:assembleDebug` and `:app:assembleRelease` |
| T-01 test input | Synthetic `FAKE_TEST_CODE_001` |
| T-02 source review | JADX `FirebaseDatabaseService` and project `firebase.json` |
| T-02 deployed-rule review | Firebase Console → Realtime Database → Rules and Rules Playground |
| T-02 isolated test environment | Firebase Realtime Database Emulator, `127.0.0.1:9000`, demo project `demo-minlish-security-lab` |
| T-02 test framework | Node.js, Firebase CLI, `@firebase/rules-unit-testing`, Firebase SDK, `curl.exe` |
| T-03 dynamic tooling | Frida CLI **17.19.0**, `frida-server` on the Android emulator, ADB, Android Logcat, Java reflection, `MutableStateFlow` |
| T-03 application state | `AuthViewModel._isUserLoggedIn`; two runtime instances found and modified |
| T-03 local Firebase lab | Firebase Authentication Emulator (`127.0.0.1:9099`) and Database Emulator (`127.0.0.1:9000`), `demo-minlish-security-lab` |
| T-03 accounts/artifacts | Synthetic `usera@minlish.example` and `userb@minlish.example`; temporary local `user-a-auth.json` and `user-b-auth.json` (contain test tokens; **do not commit**) |
| Host terminal | Windows Command Prompt (CMD) |
| Test records | Synthetic `test_user_A` (Alice, `PRIVATE_DATA_A`) and `test_user_B` (Bob, `PRIVATE_DATA_B`) |

### 2.3 Methodology

**T-01: Android logging assessment**

1. Identify the app's exported entry point and password-reset deep-link routes.
2. Trace incoming URI handling, logging statements, and `oobCode` processing in JADX.
3. Launch the activity with a synthetic deep link and capture original Debug Logcat output.
4. Inspect the original Release APK for the logging statement.
5. Replace full-URI logging with a non-sensitive event message.
6. Rebuild and retest the Debug APK with the same input; inspect the rebuilt Release APK statically.

**T-02: Firebase authorization assessment**

1. Identify client-accessible Firebase database paths and operations in `FirebaseDatabaseService`.
2. Examine available local rule configuration and rules displayed in Firebase Console.
3. Simulate authenticated/unauthenticated reads and an authenticated write under the Console rules.
4. Create a dedicated local Emulator with synthetic records and default-deny rules.
5. Compare administrator data setup with normal unauthenticated reads; reproduce public-read behavior by deliberately enabling local `.read: true`.
6. Change only the local Emulator rules to UID-scoped access and retest unauthenticated, own-user, and cross-user operations using simulated identities.
7. Separate directly observed terminal evidence, assessor-confirmed follow-up tests, and untested production conditions in the report.

**T-03: Runtime authentication-state / authorization assessment**

1. Review `AuthViewModel` and `NavGraph.kt` to identify the observed `MutableStateFlow` and its navigation consequence.
2. Attach Frida to the running app; enumerate live ViewModel instances and modify `_isUserLoggedIn` by Java reflection; record the Login → Deck UI result.
3. Independently query `FirebaseAuth.getCurrentUser()` with Frida to determine whether a genuine Firebase session exists.
4. Review the application's `/decks` read path and capture the resulting `FirebaseDB` Logcat message.
5. In an isolated **demo** Firebase Emulator, confirm effective rules by querying `/.settings/rules.json` for the exact namespace before assessing access.
6. Create synthetic User A and User B through the local Authentication Emulator, then test own-user versus cross-user GET and PUT, and clean up the synthetic test record.
7. Record the distinction between an instrumented UI, the tested live-app backend response, and the independently configured local lab.

All data values and user identifiers used in the lab are synthetic. Emulator-admin access was used for fixture setup and inspection only, not as proof of end-user authorization.

---

## 3. Security Findings

### T-01 — Potential Sensitive Data Exposure Through Deep-Link Logging

|Attribute|Assessment|
|-|-|
|Component|`com.minlish.app.presentation.main.MainActivity`|
|Affected method|`handleDeepLink(Intent)`|
|Related components|`NavGraphKt`, `Screen.ResetPassword`, `AuthRepositoryImpl`|
|Weakness|CWE-532 — Insertion of Sensitive Information into Log File|
|Severity|**Low (provisional)**|
|Status|**Remediated for the tested logging path**|
|Validation|Debug runtime reproduction and retest; Release static inspection before and after fix|

#### 3.1 Description

The original `MainActivity.handleDeepLink()` implementation wrote the complete incoming URI to Android Logcat without removing parameters or path segments that could contain sensitive values.

Static analysis also identified password-reset deep-link patterns involving `oobCode`. As a result, a password-reset URI processed by the activity could have its reset-code value included in the application's logs.

The observed behavior constitutes unredacted logging of potentially sensitive input. It **does not, by itself, prove** that another ordinary Android application can retrieve the log or that an account can be compromised.

#### 3.2 Static evidence — Before fix

**Source:** JADX decompilation of `MainActivity` from the original APK.

```java
private final void handleDeepLink(Intent intent) {
    Uri data;
    if (intent != null && (data = intent.getData()) != null) {
        Log.d("MinLishApp", "Deep link received: " + data);
    }
}
```

**Source:** `com.minlish.app.presentation.navigation.NavGraphKt`.

```java
navDeepLink.setUriPattern(
    "https://minlish.app/?mode=resetPassword&oobCode={oobCode}"
);
navDeepLink.setUriPattern(
    "https://minlish-1e2ec.firebaseapp.com/?mode=resetPassword&oobCode={oobCode}"
);
navDeepLink.setUriPattern(
    "minlish://reset_password/{oobCode}"
);
```

The navigation destination reads the argument and passes it to the password-reset screen:

```java
Bundle arguments = backStackEntry.getArguments();
String oobCode = (arguments == null)
    ? ""
    : arguments.getString("oobCode", "");
ResetPasswordScreenKt.ResetPasswordScreen(
    oobCode, function0, (Function0) objRememberedValue2,
    null, $composer, 0, 8
);
```

*The final snippet is a readability-oriented condensation of the decompiled control flow; it is not a verbatim copy of the JADX output.*

`AuthRepositoryImpl` additionally exposes password-reset verification and confirmation methods taking `oobCode` and forwarding it to `FirebaseAuthApi`. These facts establish the code's role in the password-reset feature. They do not independently establish any authorization bypass.

#### 3.3 Dynamic validation — Before fix

**Test objective:** Determine whether the incoming URI, including a synthetic reset-code value, is logged in full.

**Commands (Windows CMD):**

```cmd
adb devices
adb shell am force-stop com.minlish.app
adb logcat -c
adb shell am start -W -a android.intent.action.VIEW -d "minlish://reset_password/FAKE_TEST_CODE_001" -n com.minlish.app/com.minlish.app.presentation.main.MainActivity
adb logcat -d -s MinLishApp:D *:S
```

**Observed activity launch:**

```text
Status: ok
Activity: com.minlish.app/.presentation.main.MainActivity
Complete
```

**Observed Logcat output (28 October 2026, 10:59 local time):**

```text
10-28 10:59:40.083  9684  9684 D MinLishApp: Deep link received: minlish://reset_password/FAKE_TEST_CODE_001
```

**Result:** The complete synthetic password-reset URI appeared in the application's Logcat output. The originally hypothesized logging behavior was reproduced on the Debug APK.

#### 3.4 Release APK verification — Before fix

The unpatched Release APK was built successfully and opened in JADX. Inspection of `MainActivity.handleDeepLink()` found that the original `Log.d()` statement logging the URI remained in the Release APK.

**Result:** The risky logging statement was present in the compiled Release APK. Runtime execution of that release build was **not** demonstrated at this stage.

#### 3.5 Impact and severity rationale

Potential impact exists if a real password-reset code reaches this logging statement and the logs are available to a party or system that should not receive that code. Possible exposure environments include an authorized debugging session, privileged device access, or a log collection mechanism with inadequate access controls.

The issue is assessed as **Low (provisional)** because:

* The test demonstrates unredacted logging of a synthetic code, not theft of a valid reset credential.
* Modern Android restricts ordinary third-party applications from reading other applications' logs.
* No unauthorized log-reading path or downstream collection system was tested.
* The statement was confirmed in the original Release APK, increasing the relevance of the finding beyond Debug-only code.

No account takeover, privilege escalation, or credential reuse is claimed. The severity may be revised if the deployment environment introduces additional log exposure.

#### 3.6 Remediation

The source code was modified so that the application logs only a fixed event message, not the URI.

**Before (equivalent Kotlin form):**

```kotlin
private fun handleDeepLink(intent: Intent?) {
    intent?.data?.let { uri ->
        Log.d("MinLishApp", "Deep link received: $uri")
    }
}
```

**After:**

```kotlin
private fun handleDeepLink(intent: Intent?) {
    if (intent?.data != null) {
        Log.d("MinLishApp", "Deep link received (URI omitted)")
    }
}
```

The update retains a diagnostic indication that a deep link was received while removing the sensitive URI value from this logging call.

#### 3.7 Dynamic retest — After fix

A rebuilt Debug APK was installed and the **same synthetic deep link** was submitted after clearing Logcat.

**Commands (Windows CMD):**

```cmd
adb install -r app\build\outputs\apk\debug\app-debug.apk
adb shell am force-stop com.minlish.app
adb logcat -c
adb shell am start -W -a android.intent.action.VIEW -d "minlish://reset_password/FAKE_TEST_CODE_001" -n com.minlish.app/com.minlish.app.presentation.main.MainActivity
adb logcat -d -s MinLishApp:D *:S
```

**Observed activity launch:**

```text
Status: ok
Activity: com.minlish.app/.presentation.main.MainActivity
Complete
```

**Observed Logcat output (28 October 2026, 12:45 local time):**

```text
10-28 12:45:26.509 18136 18136 D MinLishApp: Deep link received (URI omitted)
```

The log was saved with:

```cmd
adb logcat -d -v threadtime -s MinLishApp:D *:S > C:\Minlish-debug\evidence\T01-sensitive-logging\05-logcat-after-fix.txt
```

**Verification checks:**

```cmd
findstr /C:"FAKE_TEST_CODE_001" C:\Minlish-debug\evidence\T01-sensitive-logging\05-logcat-after-fix.txt
findstr /C:"URI omitted" C:\Minlish-debug\evidence\T01-sensitive-logging\05-logcat-after-fix.txt
```

The first check returned no matching lines; the second returned the new safe logging message.

**Result: PASS.** In the filtered Logcat output for the tested run, the synthetic reset code was absent and the intended non-sensitive event message was present.

#### 3.8 Release APK verification — After fix

The patched Release APK was built successfully and inspected in JADX. The user verified that `MainActivity.handleDeepLink()` contained only the safe message:

```java
Log.d("MinLishApp", "Deep link received (URI omitted)");
```

The original full-URI logging statement was not found at that location.

**Result: PASS (static verification).** This confirms the fix was included in the inspected Release APK. **Patched Release APK runtime retesting was not performed.**

#### 3.9 Before/after comparison

|Check|Before fix|After fix|
|-|-|-|
|Activity accepts test Intent|Observed|Observed|
|Deep-link event logged|Yes|Yes|
|Synthetic `oobCode` appears in filtered app log|**Yes**|**No**|
|Debug runtime test|Behavior reproduced|**Retest passed**|
|Release static inspection|Original logging statement present|Safe logging statement present|
|Release runtime test|Not performed|Not performed|

#### 3.10 Evidence index

Evidence directory in the local report project: `evidence/T01-sensitive-logging/`.

|Intended repository path|Description|Confirmation|
|-|-|-|
|`evidence/T01-sensitive-logging/01-static-mainactivity.png`|JADX view of original URI logging|Screenshot path reserved; verify file exists before publishing|
|`evidence/T01-sensitive-logging/02-static-navgraph.png`|JADX view of reset URI patterns|Screenshot path reserved; verify file exists before publishing|
|`evidence/T01-sensitive-logging/03-adb-execution.png`|ADB command and original Logcat output|Screenshot path reserved; verify file exists before publishing|
|`evidence/T01-sensitive-logging/04-logcat-before-fix.txt`|Original logging output|User reported evidence collection completed; verify file before publishing|
|`evidence/T01-sensitive-logging/05-logcat-after-fix.txt`|Patched Debug APK output|User demonstrated save and validation commands|
|`evidence/T01-sensitive-logging/06-release-after-fix.png`|Patched Release APK shown in JADX|Screenshot path reserved; verify file exists before publishing|

**Evidence handling:** This Markdown export does not include screenshots or Logcat files stored on the Windows machine. Copy the available files into the repository at the stated paths, and remove references to any files that do not exist. Avoid committing real password-reset codes, credentials, or sensitive user data.

---

### T-02 — Time-Based Firebase Database Rules Without User-Level Authorization

| Attribute | Assessment |
|---|---|
| Component | Firebase Realtime Database; `FirebaseDatabaseService` |
| Affected paths in scope | `/users/{uid}` (with adjacent path review only) |
| Weakness | CWE-284 — Improper Access Control |
| Severity | **Provisional — potentially high historical impact; actual exposure not verified** |
| Production rules at assessment | Expired root-level time-based conditions; simulated READ/WRITE requests denied |
| Remediation status | **UID-scoped rules implemented and retested in local Emulator only** |
| Validation | Firebase Console rule inspection and Playground; isolated Emulator reproduction, remediation, and retests |

#### 3.11 Description

The Firebase Realtime Database rules shown in the MinLish Firebase Console granted root-level read and write access based on time alone. No requirement for `auth != null`, `auth.uid`, or resource ownership was present. The rule was broad enough to cover child nodes under the database root during its validity window.

This configuration had two distinct security/operational states:

- **Before expiry:** The expressions would permit ordinary clients, including unauthenticated clients, to read or write database paths without ownership checks.
- **At assessment on 28–29 October 2026:** The expressions had expired and thus denied tested client operations. Expiration is not equivalent to a correctly designed per-user authorization policy; legitimate application functions may also fail, although this operational impact was not end-to-end tested.

The configuration's potential historical impact should not be confused with proof that a real user record was exposed or tampered with in production.

#### 3.12 Static evidence — Firebase database access paths

**Source:** JADX decompilation of `com.minlish.app.data.source.remote.FirebaseDatabaseService`.

Representative decompiled operations:

```java
// The service initializes a reference to the users collection.
this.usersRef = this.database.getReference("users");

// Read user data based on the supplied UID.
this.usersRef.child(uid).get();

// Modify or delete a record based on the supplied UID.
this.usersRef.child(uid).updateChildren(map);
this.usersRef.child(uid).removeValue();

// Fetch the decks collection.
this.database.getReference("decks").get();
```

The service also accesses `vocabularyStates/{userId}/{vocabId}` and `reviewHistories/{userId}/{reviewId}`. The decompiled client code exposes operations keyed by user-controlled method arguments, but **this is not sufficient by itself to prove IDOR/BOLA**: Firebase Security Rules make the authorization decision.

The source repository's `firebase.json` referenced `"database.rules.json"`, but searches of the checked-out project (`dir /s /b database.rules.json` and `dir /s /b *rules*.json`) returned `File Not Found`. The absent local file does **not** establish the deployed rules' contents; those were examined separately in Firebase Console.

#### 3.13 Deployed rule evidence — Time-based root access

**Source:** Firebase Console → Realtime Database → Rules, as viewed during the assessment.

```json
{
  "rules": {
    ".read": "now < 1782320400000",
    ".write": "now < 1782320400000"
  }
}
```

*The original Console snippet contained date comments; comments were removed in this report for valid JSON presentation.*

The timestamp `1782320400000` equals **24 June 2026, 17:00 UTC**, or **25 June 2026, 00:00 in Vietnam (UTC+07:00)**. Both rules had expired before the assessment date. The condition checked time only and did not validate an authenticated principal or resource owner.

#### 3.14 Firebase Rules Playground — Current configuration

**Location tested:** `/users/test_user_A` using the Firebase Rules Playground (simulation, not a data read/write operation against actual user records).

| Test ID | Operation | Authentication | Expected | Observed / reported |
|---|---|---|---|---|
| T02-01 | Read / GET | OFF | DENY | **DENIED**; screenshot reviewed |
| T02-02 | Read / GET | ON, simulated UID `test_user_A` | DENY | **DENIED**; screenshot reviewed |
| T02-03 | Write / SET | ON, simulated UID `test_user_A` | DENY | **DENIED**; screenshot reviewed, but path/operation not fully visible in the supplied capture |

**Interpretation:** These results are consistent with expired time-based rules. They do not demonstrate a secure owner-based policy, since authenticated users were also denied. They also do not demonstrate a presently open production database.

#### 3.15 Isolated Emulator — Baseline setup

A separate local directory (`C:\Minlish-debug\firebase-lab`) was used, with Firebase Emulator project ID `demo-minlish-security-lab`. The database Emulator listened at `127.0.0.1:9000` and the Emulator UI at `127.0.0.1:4000`.

**Initial local rules:**

```json
{
  "rules": {
    ".read": false,
    ".write": false
  }
}
```

Synthetic fixtures:

```json
{
  "test_user_A": { "name": "Alice", "secretNote": "PRIVATE_DATA_A" },
  "test_user_B": { "name": "Bob", "secretNote": "PRIVATE_DATA_B" }
}
```

The Emulator's special `Authorization: Bearer owner` credential was used **only to seed and inspect synthetic fixtures**. A test without this credential read `/users/test_user_B` and returned:

```text
HTTP/1.1 401 Unauthorized
{"error":"Permission denied"}
```

The companion administrator fixture check returned `HTTP/1.1 200 OK` and Bob's synthetic record. These were visible together in the CMD evidence. The `owner` request is **not** an end-user authorization test because it bypasses normal Security Rules.

#### 3.16 Local reproduction — Intentionally permissive READ rule

The lab file `database.rules.json` was changed **only in the isolated Emulator** to:

```json
{
  "rules": {
    ".read": true,
    ".write": false
  }
}
```

An ordinary, unauthenticated REST GET to `/users/test_user_B` was then reported as succeeding and returning the synthetic value `PRIVATE_DATA_B`. The assessor confirmed that the test passed; the raw response was not supplied with this report.

**Result: PASS (assessor-confirmed).** This reproduces unauthorized public-read behavior under a deliberately permissive local configuration. It **does not establish that the expired time-based rule was exploited in production**. The local example keeps writes disabled and demonstrates the confidentiality aspect, not historical production modification.

#### 3.17 Impact and severity rationale

When active, root-level read/write rules without identity checks can create material confidentiality, integrity, and availability risks if private records exist beneath the database root. Potential outcomes include unauthorized inspection, changes, or deletions, subject to the actual deployed data and access conditions.

The **potential historical impact is high**, but a definitive severity score is withheld because the assessment did not establish the sensitivity or volume of production data during the active window, historical third-party access, or actual production impact. At assessment time, the rules were expired and the tested requests were denied.

#### 3.18 Local remediation — Ownership-based rules

The following rules replaced the permissive lab configuration in the **local Emulator**:

```json
{
  "rules": {
    ".read": false,
    ".write": false,
    "users": {
      "$uid": {
        ".read": "auth != null && auth.uid === $uid",
        ".write": "auth != null && auth.uid === $uid"
      }
    }
  }
}
```

The root no longer grants broad access. For the tested `/users/{uid}` path, read and write permissions require authentication and matching ownership. Because Firebase `.read`/`.write` permissions can be inherited from ancestors, a broadly allowed root rule could not be safely restricted by a child rule alone.

**Deployment caution:** This rule file is a **minimal lab remediation**, not a complete drop-in production policy for MinLish. Paths used by the application for decks, vocabularies, learning state, and review histories would need distinct, explicitly reviewed policies before any production deployment. No production rule deployment occurred.

#### 3.19 Authorization retesting — After local fix

The local rules were checked to ensure the UID conditions were present. An unauthenticated request to `/users/test_user_B` was reported as returning `401 Unauthorized` / `Permission denied` after the change.

Tests for authenticated User A used `@firebase/rules-unit-testing` with `authenticatedContext("test_user_A")`, not the Emulator administrator credential. Synthetic fixture setup used `withSecurityRulesDisabled()` solely to initialize the local test database. The test code explicitly targeted the same database namespace when seeding and reading, resolving an initial `null` data mismatch.

| Test ID | Authenticated principal | Operation / target | Expected | Result | Evidence status |
|---|---|---|---|---|---|
| T02-04 | None | READ `/users/test_user_B` under default-deny baseline | DENY | **PASS** — HTTP 401 (shown) | CMD screenshot reviewed |
| T02-05 | `test_user_A` | READ `/users/test_user_A` | ALLOW | **PASS** — Alice's synthetic record returned | CMD screenshot reviewed |
| T02-06 | `test_user_A` | READ `/users/test_user_B` | DENY | **PASS** — `assertFails()` passed | CMD screenshot reviewed |
| T02-07 | `test_user_A` | WRITE `/users/test_user_B/secretNote` | DENY, B unchanged | **PASS** — assessor confirmed | Raw console output/screenshot not independently reviewed |
| T02-08 | `test_user_A` | WRITE own `/users/test_user_A` data | ALLOW | **PASS** — assessor confirmed | Raw console output/screenshot not independently reviewed |

**Result:** The local rules passed the specified positive and negative tests on the tested user paths. The last two results are recorded as **assessor-confirmed**, rather than as independently reviewed terminal evidence. A separate authenticated User B own-read test was planned as an optional check but was not included in the confirmed test set.

#### 3.20 Before/after comparison

| Property / test | Deliberately insecure lab rule | UID-scoped lab rule |
|---|---|---|
| Root `.read` | `true` | `false` |
| Root `.write` | `false` | `false` |
| Unauthenticated client reads User B | Allowed (assessor-confirmed) | Denied |
| User A reads own record | Not specifically tested in insecure configuration | Allowed (observed) |
| User A reads User B | Not separately tested in insecure configuration | Denied (observed) |
| User A modifies User B | Not tested in insecure configuration | Denied; no change (assessor-confirmed) |
| User A modifies own record | Not tested in insecure configuration | Allowed (assessor-confirmed) |
| Production deployment | **Not applicable — Emulator only** | **Not deployed** |

**Separate production rule observation:** The actual Console configuration was **time-based and expired**, not the `.read: true` lab rule shown above. Those cases must not be conflated.

#### 3.21 Evidence index

Intended repository directory: `evidence/T02-firebase-access-control/`. These names track the lab workflow; not every image file was attached for verification with this report.

| Intended repository path | Content | Verification note |
|---|---|---|
| `01-static-firebase-service.png` | JADX user read/write/delete paths | Source text reviewed; verify screenshot exists |
| `02-firebase-security-rules.png` | Console deployed time-based rules | Rules text provided; verify screenshot exists |
| `03-unauthenticated-read-denied.png` | Console Playground read without auth | Screenshot reviewed in chat |
| `04-authenticated-read-denied.png` | Console Playground read with simulated UID | Screenshot reviewed in chat |
| `05-authenticated-write-denied.png` | Console Playground authenticated WRITE | Screenshot reviewed; operation/path not fully visible |
| `06-emulator-started.png` | Emulator ready on localhost | Screenshot reviewed in chat |
| `07-test-users-seeded.png` | Synthetic A/B fixture data | Seed confirmed indirectly by read response; screenshot not verified |
| `08-baseline-read-denied.png` | Admin fixture read vs unauthenticated 401 | Screenshot reviewed in chat |
| `09-public-read-reproduced.png` | Local permissive-rule public-read reproduction | Assessor reported PASS; verify screenshot exists |
| `10-secure-rules-unauthenticated-denied.png` | Local remediation and unauthenticated 401 | Assessor reported PASS; verify screenshot exists |
| `11-authenticated-read-tests-passed.png` | Own-read ALLOW and cross-user read DENY | Screenshot reviewed in chat |
| `12-cross-user-write-denied.png` | Cross-user WRITE DENY; User B value unchanged | Assessor confirmed PASS; add/verify console screenshot |
| `13-own-user-write-allowed.png` | Own-user WRITE ALLOW | Assessor confirmed PASS; add/verify console screenshot |

**Evidence handling:** Before publishing to GitHub, confirm each referenced file exists and its contents match the described test. Do not commit Firebase production credentials, tokens, service account keys, personal user data, or potentially sensitive console configuration beyond what is authorized for disclosure.

#### 3.22 Limitations and conclusion for T-02

- The Console rules had already expired by the assessment. The tested production-rule simulations were **denied**; no current production authorization bypass was demonstrated.
- It is not known whether private production data was present or accessed during the prior open window, nor whether any historical abuse occurred.
- The `.read: true` reproduction was **deliberate and local**. It demonstrates what a public-read policy does in an Emulator, not evidence of exploitation of the live database.
- Remediation tests were limited to `/users/{uid}`; other database paths were not fully authorized or tested.
- Emulator test results used synthetic identities and synthetic records, not real Firebase accounts.
- No fixes were deployed to production as part of this assessment.

**T-02 conclusion:** MinLish's displayed Firebase rules lacked owner-level authorization and historically would have permitted broad read/write access until expiry. UID-scoped rules were implemented and passed the described authorization tests in a local Emulator. Production migration, path-specific policy design, and independent validation remain follow-up actions.

---

### T-03 — Client-Side Authentication State Manipulation and Navigation Bypass

| Attribute | Assessment |
|---|---|
| Component | `com.minlish.app.presentation.auth.viewmodel.AuthViewModel`; `NavGraph.kt` |
| Related code | `DeckViewModel`, `BunnyRepositoryImpl`, `FirebaseDatabaseService` |
| Weakness | Client-side trust / authentication-state manipulation; **potential CWE-602 mapping** limited to client-side enforcement (not a demonstrated server-side authorization failure) |
| Severity | **Low (provisional)** — demonstrated UI navigation impact only |
| Status | **Client-side Login → Deck navigation bypass confirmed**; Firebase Authentication bypass and production backend authorization bypass **not demonstrated** |
| Validation | Frida runtime instrumentation, independent FirebaseAuth check, Logcat observation, separate local Auth/Realtime Database Emulator UID-rule tests |

#### 3.23 Description and hypothesis

MinLish exposes a navigation decision driven by an in-memory authentication state in `AuthViewModel`. The local Android process is under the control of a sufficiently privileged tester with Frida access; therefore, its private fields and observable state can be instrumented. The test objective was to determine **whether changing only the client-side state could reach a post-login screen**, and whether that implied a valid Firebase session or backend access.

The test established a **navigation bypass**, not the creation of a genuine Firebase-authenticated session. This distinction is central to the severity assessment.

#### 3.24 Static analysis — Source-to-navigation trace

`AuthViewModel` declares a private state flow observed by navigation code:

```kotlin
private val _isUserLoggedIn = MutableStateFlow<Boolean?>(null)
```

Successful login-related flows set the value to `true`; a sign-out/check path sets it to `false`. In `NavGraph.kt`, the observed authentication state drives navigation to `Screen.ListOfDeck.route` when it becomes `true`. The exact navigation action is client-side behavior; it is **not** a server-issued credential or authorization grant.

`DeckViewModel` subscribes to `repository.getDecks()` and initializes a deck list. In `BunnyRepositoryImpl`, `getDecks()` delegates to `FirebaseDatabaseService.getDecks()`. The remote service issues a Firebase Realtime Database read at `/decks`:

```kotlin
val snapshot = database.getReference("decks").get().await()
```

When that call fails, its exception handler logs an error and returns an empty list. A visible Deck screen therefore does **not** establish that private deck records were retrieved. Additionally, `BunnyRepositoryImpl` has a fallback user ID:

```kotlin
private fun getCurrentUserId(): String =
    authApi.getCurrentUser()?.uid ?: "guest_user"
```

The fallback creates a **potential** shared-guest-namespace concern if backend rules allow access. It is not independent proof of unauthorized production access.

#### 3.25 Dynamic test setup and Frida attachment

**Environment:** Running app `com.minlish.app` on an Android Emulator with an authorized local `frida-server`; Frida CLI **17.19.0**; Windows CMD, ADB, and Logcat.

**Representative attach sequence:**

```cmd
adb devices
adb shell pidof com.minlish.app
frida -U -p <PID>
```

`<PID>` must be replaced with the app's **current** process ID; a restarted app may have a new PID. The JavaScript below was executed in the Frida REPL attached to that process. The test requires a debug/instrumentable emulator setup; no bypass of Android OS privileges is claimed.

#### 3.26 Frida Script #1 — Modify authentication state at runtime

**Objective:** Enumerate live `AuthViewModel` objects, access the private `_isUserLoggedIn` field, and set each instance's `MutableStateFlow` value to `true`, without invoking a legitimate sign-in API.

**Frida JavaScript — executed in the attached REPL:**

```javascript
Java.perform(function () {
    const name = "com.minlish.app.presentation.auth.viewmodel.AuthViewModel";
    const AuthVM = Java.use(name);
    const StateFlow = Java.use("kotlinx.coroutines.flow.MutableStateFlow");
    const JavaBoolean = Java.use("java.lang.Boolean");
    const field = AuthVM.class.getDeclaredField("_isUserLoggedIn");
    field.setAccessible(true);

    let count = 0;
    Java.choose(name, {
        onMatch: function (instance) {
            count++;
            const flow = Java.cast(field.get(instance), StateFlow);
            console.log("[T03] Instance #" + count + " BEFORE: " + flow.getValue());
            flow.setValue(JavaBoolean.TRUE.value);
            console.log("[T03] Instance #" + count + " AFTER: " + flow.getValue());
        },
        onComplete: function () {
            console.log("[T03] Instances found: " + count);
        }
    });
});
```

**Script technique mapping:**

| Function / API | What it did in this test |
|---|---|
| `Java.perform()` | Runs the callback in Frida's Java runtime context |
| `Java.use()` | Resolves the target ViewModel class and helper Java interfaces/classes |
| `Java.choose()` | Finds **existing** instances of the ViewModel on the managed heap |
| `getDeclaredField("_isUserLoggedIn")` | Obtains the private state field by name |
| `setAccessible(true)` | Allows reflective access to the private field |
| `Java.cast(..., MutableStateFlow)` | Accesses the field through its state-flow interface |
| `flow.setValue(JavaBoolean.TRUE.value)` | Forces the observed login-state value to `true` in memory |

**Observed evidence (representative console output):**

```text
[T03] Instance #1 BEFORE: false
[T03] Instance #1 AFTER: true
[T03] Instance #2 BEFORE: false
[T03] Instance #2 AFTER: true
[T03] Instances found: 2
```

An earlier attempt changed only one ViewModel instance and did **not** trigger the expected navigation. After both instances were set to `true`, the assessor observed MinLish navigate from **Login** to **“Bộ từ vựng của tôi”** (Deck screen).

**Result: PASS — client-side navigation bypass reproduced.** The script modifies in-memory state only; it does **not** authenticate with Firebase, obtain an ID token, or modify backend Security Rules.

#### 3.27 Frida Script #2 — Verify actual Firebase Authentication state

**Objective:** Determine whether the navigation result represented a genuine authenticated Firebase session, rather than merely a changed UI variable.

**Frida JavaScript — executed while the application showed the Deck screen:**

```javascript
Java.perform(function () {
    const FirebaseAuth = Java.use("com.google.firebase.auth.FirebaseAuth");
    const user = FirebaseAuth.getInstance().getCurrentUser();
    console.log("[T03] Firebase authenticated: " + (user !== null));
    console.log("[T03] Firebase session: " + (user === null ? "SIGNED OUT" : "SIGNED IN"));
});
```

**Observed output:**

```text
[T03] Firebase authenticated: false
[T03] Firebase session: SIGNED OUT
```

**Result:** The app displayed a post-login screen despite `FirebaseAuth.getCurrentUser()` returning `null`. **Firebase Authentication bypass was not demonstrated.** `getCurrentUser() == null` is a direct SDK state observation, not a general proof of the absence of every conceivable credential elsewhere in the process.

#### 3.28 Backend request and Logcat evidence

After client-side manipulation, an app request to retrieve `/decks` produced the following Logcat entry:

```cmd
adb logcat -d -v time -s FirebaseDB:D "*:S"
```

```text
10-29 21:59:17.613 E/FirebaseDB( 5358): Error fetching decks: Permission denied
```

`FirebaseDatabaseService.getDecks()` catches the failed Firebase read and returns an empty list. This observed denial shows that the navigation bypass **did not grant access to `/decks` in this specific signed-out run**. It does **not** prove every database path is protected correctly, or that production Firebase authorization has been comprehensively reviewed.

#### 3.29 Separate local lab — Effective rules versus the rules file

For isolated authorization tests, a demo Firebase project `demo-minlish-security-lab` was configured with:

- Authentication Emulator: `127.0.0.1:9099`.
- Realtime Database Emulator: `127.0.0.1:9000`.
- Local rules file: `C:\Minlish-debug\firebase-lab\database.rules.json` referenced by `firebase.json`.

The lab initially returned `HTTP 200` and `null` for unauthenticated reads of `/vocabularyStates/guest_user` and `/reviewHistories/guest_user`. An unauthenticated PUT to `/reviewHistories/guest_user/T03_FAKE_001` also returned `HTTP 200` with the synthetic record. The test record was deleted and a subsequent GET returned `null` (with `HTTP 200` because the **read permission**, not the data, remained open).

**Important diagnostic step:** The file on disk defined default-deny rules, but querying the **effective** rules for the exact namespace showed a permissive configuration:

```cmd
curl -i -H "Authorization: Bearer owner" "http://127.0.0.1:9000/.settings/rules.json?ns=demo-minlish-security-lab"
```

```json
{
  "rules": {
    ".read": true,
    ".write": true
  }
}
```

This also explained an initial **misleading `HTTP 200`** when User B attempted to read User A's path after emulator restarts. The `200` occurred under **open lab rules**; it is not evidence that properly applied UID rules were bypassed. Rules were re-applied to the correct namespace and re-read before meaningful owner-scope tests.

**Local rules applied for the scoped tests:**

```json
{
  "rules": {
    ".read": false,
    ".write": false,
    "users": {
      "$uid": {
        ".read": "auth != null && auth.uid === $uid",
        ".write": "auth != null && auth.uid === $uid"
      }
    },
    "vocabularyStates": {
      "$uid": {
        ".read": "auth != null && auth.uid === $uid",
        ".write": "auth != null && auth.uid === $uid"
      }
    },
    "reviewHistories": {
      "$uid": {
        ".read": "auth != null && auth.uid === $uid",
        ".write": "auth != null && auth.uid === $uid"
      }
    }
  }
}
```

**Rules reload example — Emulator only:**

```cmd
curl -i -X PUT -H "Authorization: Bearer owner" -H "Content-Type: application/json" --data-binary "@database.rules.json" "http://127.0.0.1:9000/.settings/rules.json?ns=demo-minlish-security-lab"
```

The special `Authorization: Bearer owner` header was used **only to administer or inspect local emulator rules**. It was **not** included in the normal client read/write tests. No production database rules were changed.

#### 3.30 Synthetic User A / User B authorization matrix

User A (`usera@minlish.example`) and User B (`userb@minlish.example`) were created through the local Authentication Emulator (`signUp` returned `HTTP 200` for each). Temporary `user-a-auth.json` and `user-b-auth.json` files contained the resulting local UID and ID token for subsequent requests; raw tokens are omitted from this report.

The requests used each account's `idToken` as the Firebase Realtime Database REST API `auth` parameter and targeted the database namespace `demo-minlish-security-lab`.

| Test ID | Scenario | Observed status | Assessment |
|---|---|---|---|
| T03-A01 | Unauthenticated GET `/vocabularyStates/{User A UID}` after default-deny rule load | **HTTP 401** | Denied — PASS |
| T03-A02 | User A GET own `/vocabularyStates/{User A UID}` after UID rule load | **HTTP 200** | Allowed — PASS |
| T03-A03 | User B GET `/vocabularyStates/{User A UID}` under **open** local rules | **HTTP 200** | Test invalid for UID-rule verification; diagnosed configuration mismatch |
| T03-A04 | User B GET `/vocabularyStates/{User A UID}` after effective UID rules were verified | **HTTP 401** | Denied — PASS |
| T03-A05 | User B PUT `/vocabularyStates/{User A UID}/T03_CROSS_WRITE` | **HTTP 401** | Denied — PASS |
| T03-A06 | User A GET own `/vocabularyStates/{User A UID}` after UID rule load (repeat) | **HTTP 200** | Allowed — PASS |
| T03-A07 | User A PUT own `/vocabularyStates/{User A UID}/T03_OWN_WRITE` | **HTTP 200** | Allowed — PASS |
| T03-A08 | User A DELETE own synthetic `T03_OWN_WRITE` | **HTTP 200** | Cleanup request succeeded; no separate post-delete GET was supplied |

The HTTP status values above were shared directly by the assessor in the chat; only the statuses were supplied for some commands, not full independently archived terminal transcripts. An `HTTP 200` read of a missing resource may return `null`; this still confirms the access rule allows that read, **not** that private data exists.

**Finding from local lab:** Once the correct UID-scoped rules were active, the specified own-user operations were permitted and cross-user operations denied. This is a **synthetic, locally configured authorization test**, not a production MinLish exploit or a production rule deployment.

#### 3.31 Reproduction details — Cross-user read using local tokens

**Example testing logic (PowerShell from Windows CMD; token is not printed):**

```cmd
powershell -NoProfile -Command "$a=Get-Content 'user-a-auth.json' | ConvertFrom-Json; $b=Get-Content 'user-b-auth.json' | ConvertFrom-Json; $url='http://127.0.0.1:9000/vocabularyStates/'+$a.localId+'.json?ns=demo-minlish-security-lab&auth='+$b.idToken; try {$r=Invoke-WebRequest -UseBasicParsing -Uri $url -ErrorAction Stop; 'User B reads User A: HTTP '+[int]$r.StatusCode} catch {if ($_.Exception.Response) {'User B reads User A: HTTP '+[int]$_.Exception.Response.StatusCode} else {$_.Exception.Message}}"
```

**Expected and observed after UID rules were correctly applied:**

```text
User B reads User A: HTTP 401
```

The same test returned `HTTP 200` when the effective lab rules were accidentally permissive. That earlier response must not be used to infer a bypass of the owner-scoped rule.

#### 3.32 Impact and severity rationale

**Demonstrated:** A local actor capable of runtime instrumentation changed the client's login-state flow and reached the Deck screen while Firebase Authentication was signed out.

**Not demonstrated:** Authentication-token forgery, unauthorized retrieval of `/decks`, access to another user's private records in the live service, production backend privilege escalation, or production data modification.

**Low (provisional)** applies only to the confirmed client-side navigation effect. Severity could rise if future testing finds sensitive local data or privileged features accessible without independent authorization. The use of Frida on a controlled emulator should not be equated with remote exploitation of an ordinary device.

#### 3.33 Recommended remediation and regression tests

1. Treat ViewModel state as **UI/navigation state**, not as a security boundary; enforce per-user authorization in Firebase Security Rules (and any other trusted backend).
2. Derive the displayed signed-in state consistently from Firebase Authentication and handle sign-in/sign-out/session changes to minimize misleading post-login navigation.
3. Avoid a shared `guest_user` fallback for user-private data unless a clear guest-data isolation design exists and is enforced by rules.
4. Keep default-deny root rules, apply path-specific `auth.uid === $uid` checks for user-owned branches, and separately design access policies for public/private decks and shared vocabularies.
5. Add `.validate` / schema and permissible-value constraints to write rules; UID equality alone does not validate record content.
6. Use automated positive and negative tests: unauthenticated read/write denial; own-user read/write success; cross-user read/write/delete denial; session loss; UI navigation after sign-out.
7. Test the app with restricted Firebase responses and verify that the UI displays an appropriate signed-out/error state rather than implying protected data was loaded.
8. Verify **effective** emulator/database namespace rules before accepting results; do not infer active rules only from `database.rules.json` on disk.

#### 3.34 Evidence index — T-03

Suggested directory if the corresponding artifacts are collected: `evidence/T03-client-auth-state/`. **The Markdown attachment does not contain these screenshots, saved scripts, or Logcat files; paths below are proposed, not verified.**

| Suggested artifact | What it should capture | Evidence status |
|---|---|---|
| `01-authviewmodel-navgraph-source.png` | StateFlow definition and navigation observer | Source code was described/reviewed; screenshot not verified |
| `02-frida-state-manipulation.js` | Frida Script #1 above | Script included verbatim in this report; standalone file not verified |
| `03-frida-console-state.png` | Two instances changed to `true` | Assessor/test interaction reported; screenshot not verified |
| `04-login-to-deck-ui.png` | UI before/after state manipulation | Assessor observed navigation; screenshot not verified |
| `05-frida-firebase-session.js` | Frida Script #2 above | Script included verbatim in this report; standalone file not verified |
| `06-frida-firebase-signed-out.png` | `Firebase authenticated: false`; `SIGNED OUT` | Console values were observed in prior interaction; screenshot not verified |
| `07-logcat-decks-denied.txt` | `FirebaseDB` permission denial at `10-29 21:59:17.613` | Exact Logcat line shared in chat; local file not verified |
| `08-emulator-effective-rules.txt` | Initially open rules, then verified UID rules | REST responses shared; local file not verified |
| `09-local-authz-test-matrix.txt` | Local User A/B HTTP status outputs | Individual statuses shared; consolidated file not verified |

**Evidence handling:** The actual Frida console, Logcat, and lab responses should be saved/redacted before publication. Do **not** commit `user-a-auth.json`, `user-b-auth.json`, real Firebase keys, refresh tokens, or other credentials. Do not represent proposed evidence paths as existing files.

#### 3.35 Limitations and T-03 conclusion

- The test was performed against an instrumentable Android emulator. It proves local runtime state tampering, not a remotely exploitable login bypass.
- Two `AuthViewModel` instances were altered; the specific lifecycle relationship between them was not resolved. The UI navigation itself was observed after both were changed.
- Firebase Authentication remained signed out. The observed `/decks` request was denied by Firebase; other live backend paths were not comprehensively tested.
- Local permissive-rule responses and local UID-rule passes are **environment-specific**. Restarts temporarily restored open rules in the targeted namespace until they were re-applied; that diagnostic finding explains test discrepancies, not a live Firebase defect.
- A successful `DELETE` response for the final test fixture was observed, but there was no independently supplied read-after-delete response for that final fixture.
- No client code fix for the navigation bypass, complete production rules deployment, or patched MinLish regression test was performed as part of T-03.

**T-03 conclusion:** The client-side login-state flow can be manipulated with Frida to reach the Deck screen while `FirebaseAuth` remains signed out; the tested `/decks` read was denied. Independent local Firebase Emulator testing showed UID-scoped rules rejecting cross-user reads/writes while permitting owner reads/writes. **Client-side navigation bypass is confirmed; Firebase Authentication bypass and production backend authorization bypass are not demonstrated.**

---

## 4. Overall Recommendations

1. **Eliminate logging of authentication-related URI values.** Log a fixed event label rather than full deep links, reset codes, query strings, or headers.
2. **Review adjacent Android logging paths.** Inspect `Log.d`, `Log.i`, `Log.e`, `println`, and network interceptors for unintended credential, URL, or response-body exposure.
3. **Verify fixes in release artifacts.** Where practical, use a signed release-equivalent build for a runtime smoke test and review production telemetry/logging destinations.
4. **Replace production time-based Firebase rules with a reviewed, comprehensive access-control policy.** The local `/users/{uid}` rule is only a starting point; establish authorization and validation requirements for `/decks`, `/deck_vocabularies`, `/vocabularyStates`, `/reviewHistories`, and other used paths before deploying.
5. **Apply least privilege and verify both positive and negative cases.** Use server-side `auth.uid` checks and data validation; test own-user allowed, cross-user denied, unauthenticated denied, and unauthorized delete/overwrite attempts as appropriate.
6. **Keep Firebase rules version-controlled and deployed through a reviewed process.** The project referenced a missing `database.rules.json`; reconcile repository configuration with the deployed Console rules to reduce configuration drift.
7. **Stage a production rule migration safely.** Use a dedicated staging environment and rules tests before changing live rules, and confirm legitimate reads/writes continue to work. Avoid directly deploying the minimal lab example unchanged.
8. **Preserve reproducible, non-sensitive evidence.** Attach actual screenshots and command outputs; label assessor-reported results when original outputs are unavailable. Never include real credentials or user records in the portfolio.
9. **Do not treat client-side login-state flags as authorization.** Keep screen navigation synchronized with actual authentication state, but require backend authorization for protected resources; include sign-out and runtime-state-manipulation regression checks.
10. **Eliminate ambiguity in local emulator rule state.** Verify `/.settings/rules.json` on the exact namespace after emulator restarts, since an open local database invalidates negative authorization tests even if the rules file is strict.

## 5. Conclusion

Three test areas were evaluated in this focused assessment.

**T-01:** An original Debug APK logged complete password-reset deep links, including a synthetic reset-code value. The logging call was changed to a non-sensitive event message. Debug retesting and Release APK static verification passed for the tested code path. Runtime validation of the patched Release APK and an unauthorized log-access scenario remain untested.

**T-02:** The displayed Firebase Realtime Database rules were time-based root permissions without authentication or ownership checks. Their historical validity window expired on 25 June 2026, before the assessment, so Console Playground tests denied the simulated operations at the assessment date. An isolated local Emulator reproduced public-read risk under deliberately permissive rules, then demonstrated the expected protections under UID-scoped user rules. The final cross-user and own-user write outcomes were confirmed by the assessor; their raw output images must be included before claiming independently reviewed evidence.

**T-03:** Frida Script #1 modified the private `_isUserLoggedIn` state in two live `AuthViewModel` instances; the assessor observed Login → Deck navigation. Frida Script #2 independently checked Firebase Authentication and found the session still `SIGNED OUT`. The app's `/decks` Firebase read was rejected with `Permission denied`. Additional synthetic User A/B tests in the isolated Firebase Emulator confirmed that correctly applied UID-scoped rules allow owner reads/writes and deny cross-user reads/writes. The initial cross-user `HTTP 200` was traced to **permissive local rules**, not a successful bypass of UID rules. No production backend authorization bypass was demonstrated.

**Disposition:** T-01 is remediated for the specifically tested logging path. T-02 is **locally remediated and retested**. T-03's **client-side navigation bypass is reproduced but not remediated**, with only a provisional Low severity given the demonstrated UI-only impact. The production Firebase project was **not modified** in this assessment. No unauthorized production database access, historic data exposure, or account takeover is claimed. The work demonstrates a repeatable process for hypothesis formation, static review, controlled reproduction, runtime instrumentation, remediation, retesting, and evidence-scoped reporting.

---

*Prepared as an evidence-based AppSec portfolio assessment. All password-reset values, Firebase test users, and local test records used in the tests were synthetic. The local Frida scripts demonstrate a client-side workflow bypass only; production exposure and deployment conclusions are expressly limited as stated above.*
