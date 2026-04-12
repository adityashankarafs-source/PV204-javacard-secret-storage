# PV204 JavaCard Secret Storage Structure & Instructions

## Features

- **Secret storage**: store name-value pairs on the card (up to 10 secrets, 32-byte names, 64-byte values)
- **Listing**: enumerate stored secret names
- **Retrieval**: retrieve a stored secret's value (PIN-gated)
- **PIN management**: change PIN via authenticated command
- **Secure channel**: nonce-based mutual authentication with a hash-derived session key, replay protection via monotonic counter, MAC-authenticated encrypted commands, and per-direction keystream encryption
- **Persistent master key**: provisioned once via `init`, then card remains bound to that key across sessions

## Requirements

- Java 8 (JDK 1.8) — required by the JavaCard SDK
- Linux, macOS, or Windows
- The Gradle wrapper is included; no separate Gradle installation needed

On Debian/Ubuntu Linux:

```
sudo apt install openjdk-8-jdk
```

## Building

From the project root:

```
./gradlew build
```

This compiles both the applet (under `applet/src/main/java/applet/`) and the client (under `client/src/main/java/com/pv204/client/`), runs all unit tests, and produces a `.cap` file for the applet under `applet/build/javacard/`.

To build without running tests:

```
./gradlew assemble
```

## Running the client

```
./gradlew --console=plain run
```

This launches an interactive REPL that talks to a `MainApplet` instance running inside a jCardSim simulator (no physical card required).

## Demo flow

Once the REPL is running, walk through the following commands to exercise the full functionality:

```
init 0102030405060708090a0b0c0d0e0f10
open
verify 1234
store gmail mypassword
store github anothersecret
list
get gmail
change-pin 1234 5678
verify 5678
exit
```

Expected output:

- `init` → "Master key initialized."
- `open` → "Secure channel opened."
- `verify` → "PIN verified."
- `store` → "Secret stored: gmail"
- `list` → prints `- gmail` and `- github`
- `get gmail` → prints `mypassword`
- `change-pin` → "PIN changed successfully."
- `verify 5678` → "PIN verified."

The default PIN on a freshly installed applet is `1234`. The master key can be any 16-byte value (32 hex characters or 16 ASCII characters).

## Commands

| Command | Description |
|---|---|
| `init <key>` | Provision the master key. 32 hex chars or 16 ASCII chars. Can only be done once per card lifetime. |
| `open` | Establish a secure channel with the card. |
| `verify <pin>` | Authenticate with the PIN. Required before `store`, `get`, `list`, and `change-pin`. |
| `store <name> <value>` | Store a name-value pair. |
| `list` | List the names of all stored secrets. |
| `get <name>` | Retrieve the value of a stored secret. |
| `change-pin <old> <new>` | Change the PIN. |
| `help` | Show command list. |
| `exit` | Quit the REPL. |

## Running tests

```
./gradlew test
```

Test suites:

- `applet.MainAppletTest` — verifies that plain (non-secure) command variants are rejected, and that the master-key initialisation flow is enforced correctly.
- `applet.MainAppletWithSecurity` — end-to-end secure channel tests: handshake, encrypted command round trips, MAC tampering detection, replay detection.

All tests run inside jCardSim without requiring physical hardware.

## Project structure

```
.
├── applet/
│   ├── build.gradle
│   └── src/
│       ├── main/java/applet/
│       │   ├── Constants.java          # Protocol constants and SW codes
│       │   ├── MainApplet.java         # Applet entry point and secure channel
│       │   └── SecretStore.java        # In-card secret storage
│       └── test/java/applet/
│           ├── MainAppletTest.java
│           └── MainAppletWithSecurity.java
├── client/
│   └── src/main/java/com/pv204/client/
│       ├── Main.java                   # CLI entry point and REPL
│       ├── InteractiveMain.java        # Wrapper used by Gradle's `run` task
│       ├── CardManager.java            # High-level command dispatcher
│       ├── SecureSession.java          # Client-side secure channel
│       ├── ApduTransport.java          # Transport interface
│       ├── JCardSimTransport.java      # jCardSim-backed transport
│       └── ...                         # Supporting data classes
├── docs/
│   ├── apdu-protocol.md                # APDU command reference
│   ├── architecture.md                 # System architecture overview
│   ├── client-usage.md                 # Detailed client usage notes
│   ├── demo-flow.md                    # Step-by-step demo walkthrough
│   ├── test-scenarios.md               # Test case descriptions
│   ├── my-work.md                      # Khaled's individual contributions
│   └── aditya-work.md                  # Aditya's individual contributions
├── settings.gradle
└── README.md
```

## Security model

The applet implements a custom secure channel protocol with the following properties:

- **Mutual authentication**: client and card both prove knowledge of the shared master key via nonce exchange and a handshake proof.
- **Session keys**: derived as `SHA-256(masterKey || clientNonce || cardNonce || 0x11)[:16]`. Different from the handshake proof (`SHA-256(... || 0x7A)`) and the keystream (`SHA-256(sessionKey || counter || blockIndex || direction || 0x22)`) via domain separation bytes.
- **Replay protection**: monotonic 16-bit counter, incremented on every successful request. Replayed APDUs are rejected.
- **Authenticated encryption**: each secure command is framed as `counter || ciphertext || MAC`, where MAC binds the session key, the request direction, the instruction byte, the data length, and the ciphertext.
- **MAC-first verification**: the MAC is checked before the counter, and both failure paths return the same status word, preventing oracle attacks against the expected counter value.
- **Transient session state**: session keys, nonces, and intermediate cryptographic buffers are stored in `CLEAR_ON_DESELECT` transient memory to ensure they do not persist across card sessions.
- **Persistent master key with one-time provisioning**: the master key is stored in persistent memory and `INS_INIT_MASTER_KEY` refuses to overwrite an already-provisioned key, preventing a denial-of-service attack where an unauthenticated attacker re-initialises the card.

### Known limitations

The following items are deliberate design choices or known limitations that we acknowledge in the spirit of the assignment's break-it review phase:

- **MAC construction**: the MAC is computed as `SHA-256(sessionKey || direction || ins || dataLen || data)`, which is theoretically vulnerable to length-extension attacks against the underlying Merkle-Damgård hash function. A production implementation would use HMAC-SHA256 (available on JavaCard 3.0.4+) to eliminate this class of attack. This was not done due to the additional bilateral integration risk.
- **Single session key**: the same `sessionKey` is used both as the input to the MAC and as the input to the keystream generator. Best practice is to derive separate subkeys (`K_enc`, `K_mac`) so that a vulnerability in one primitive cannot compromise the other.
- **`list` requires PIN**: the assignment specification only requires PIN authentication for `get`, but we chose to require it for `list` as well. This provides defence in depth (an attacker who has compromised the secure channel cannot enumerate stored secret names without also knowing the PIN), at the cost of slightly stricter usability.
- **Response MAC INS binding**: response MACs use `ins = 0x00` instead of the originating request's INS byte. This weakens the request/response correlation but does not enable any practical attack given the per-message counter.
- **Hardcoded default PIN**: a freshly installed applet uses PIN `1234`. In a production deployment, the initial PIN would be chosen during card personalisation.
- **Plaintext key provisioning**: the `INS_INIT_MASTER_KEY` command sends the master key in plaintext over the APDU channel during the one-time provisioning step. In a real deployment this would happen during card personalisation in a controlled environment, not over the user's APDU channel.

## License

MIT License — see [LICENSE](LICENSE).
