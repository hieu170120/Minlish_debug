
const fs = require("node:fs");

const {
  initializeTestEnvironment,
  assertSucceeds,
  assertFails
} = require("@firebase/rules-unit-testing");

const DATABASE_URL =
  "https://demo-minlish-security-lab-default-rtdb.firebaseio.com";

async function main() {
  const testEnv = await initializeTestEnvironment({
    projectId: "demo-minlish-security-lab",
    database: {
      host: "127.0.0.1",
      port: 9000,
      rules: fs.readFileSync("database.rules.json", "utf8")
    }
  });

  try {
    // SETUP: Create synthetic data with rules bypassed
    await testEnv.withSecurityRulesDisabled(async (context) => {
      const db = context.database(DATABASE_URL);

      await db.ref("users/test_user_A").set({
        name: "Alice",
        secretNote: "PRIVATE_DATA_A"
      });

      await db.ref("users/test_user_B").set({
        name: "Bob",
        secretNote: "PRIVATE_DATA_B"
      });
    });

    console.log("[SETUP] Test data created");

    // Authenticated as User A
    const userA = testEnv.authenticatedContext("test_user_A");
    const dbA = userA.database(DATABASE_URL);

    // TEST 1: User A reads own data
    const ownData = await assertSucceeds(
      dbA.ref("users/test_user_A").once("value")
    );

    console.log("Actual User A data:", JSON.stringify(ownData.val()));

    if (ownData.val()?.secretNote !== "PRIVATE_DATA_A") {
      throw new Error("User A test data is missing or incorrect");
    }

    console.log("[PASS] User A can read own data");

    // TEST 2: User A tries reading User B's data
    await assertFails(
      dbA.ref("users/test_user_B").once("value")
    );

    console.log("[PASS] User A cannot read User B's data");
    console.log("\n2/2 authorization tests PASSED");

  } finally {
    await testEnv.cleanup();
  }
}

main().catch((error) => {
  console.error("[FAIL]", error.message);
  process.exitCode = 1;
});
