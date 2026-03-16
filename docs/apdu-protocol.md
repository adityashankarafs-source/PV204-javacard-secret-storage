# APDU Protocol

## Instruction Codes

- `0x10` STORE_SECRET
- `0x20` LIST_SECRETS
- `0x30` GET_SECRET
- `0x40` CHANGE_PIN

## Command Formats

### STORE_SECRET
Input:
[nameLen][name][valueLen][value]

Example:
[5][gmail][10][mypassword]

### LIST_SECRETS
Input:
none

Output:
newline-separated secret names

### GET_SECRET
Input:
[pinLen][pin][nameLen][name]

Example:
[4][1234][5][gmail]

Output:
secret value bytes

### CHANGE_PIN
Input:
[oldPinLen][oldPin][newPinLen][newPin]

Example:
[4][1234][4][5678]

Output:
success status word only

## Status Words

- `0x6A88` secret not found
- `0x6A84` storage full
- `0x6300` invalid PIN
- `0x6A80` invalid data