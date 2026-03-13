# Test Scenarios

## Current Client-Level Tests

1. Run without arguments
   - Expected: help message is shown

2. Run help
   - Expected: help message is shown

3. Add secret
   - Command: add gmail mypassword
   - Expected: store command is simulated and success message is shown

4. List secrets
   - Command: list
   - Expected: list command is simulated and secret names are shown

5. Get secret
   - Command: get gmail
   - Expected: get command is simulated and a mock secret value is shown

6. Change PIN
   - Command: change-pin 1234 5678
   - Expected: change-pin command is simulated and success message is shown

## Later Integration Tests
- add a secret through the client and verify it is stored on the applet
- retrieve a secret only after correct PIN verification
- reject access on wrong PIN
- verify PIN change works