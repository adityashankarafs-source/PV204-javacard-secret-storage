# Project Architecture

## Components
1. Client Application
2. JavaCard Applet
3. Secure Communication Layer
4. Secret Storage Module

## Workflow
- The user enters a command in the client application.
- The client converts the command into a request.
- The JavaCard applet processes the request.
- For sensitive operations, PIN verification is required.
- The applet returns a response.

## Responsibilities
### Client
- Parse user input
- Send commands to card/app simulator

### Applet
- Store secrets
- List secret names
- Verify PIN
- Return requested secret
- Change PIN

### Secure Layer
- Protect communication between client and smartcard