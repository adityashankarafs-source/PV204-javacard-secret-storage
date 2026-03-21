Changes for adding security:
- authenticated secure-channel opening with client nonce, card nonce, and card proof
- session-key derivation from shared master key + nonces
- per-message replay protection using a monotonic 16-bit counter
- secure APDU framing: counter || ciphertext || MAC
- protected responses for secure list/get
- client-side secure-session implementation
- replacement of the mock client path with a jCardSim-backed transport
- CLI update so PIN is supplied for commands that require authentication

Important limitation:
- The confidentiality layer uses a SHA-256-derived XOR keystream, which works for the prototype for now, but will be modified for phase 3.

Updated CLI examples:
- add <pin> <name> <value>
- list
- get <pin> <name>
- change-pin <oldPin> <newPin>
