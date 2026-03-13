
# PV204-javacard-secret-storage

## PV204 JavaCard Secret Storage Project

### Team Members
- Aditya Shankar
- Ujjawal Kumar
- Khaled Kamal Hegazy

## Project Description
This project implements a secure secret storage system using JavaCard technology.

The system allows:
- storing secrets securely on a smartcard
- listing stored secret names
- retrieving secrets after PIN verification
- changing the PIN securely

## Repository Structure
- `applet/` — JavaCard applet code
- `client/` — client application
- `docs/` — architecture and project documentation
- `tests/` — test cases
- `README.md` — project overview

## Technology Stack
- JavaCard
- Java
- jCardSim
- Gradle

## Current Project Status
- initial client prototype implemented
- architecture documentation prepared
- usage and test scenario documents prepared
- ready for integration with applet and secure communication

## Visible Client Features
- help command
- add secret command
- list secrets command
- get secret command
- change-pin command

## Example Commands

```bash
java -cp client/src/main/java com.pv204.client.Main help
java -cp client/src/main/java com.pv204.client.Main list
java -cp client/src/main/java com.pv204.client.Main add gmail mypassword
java -cp client/src/main/java com.pv204.client.Main get gmail
java -cp client/src/main/java com.pv204.client.Main change-pin 1234 5678
## Example Commands

```bash
java -cp client/src/main/java com.pv204.client.Main list
java -cp client/src/main/java com.pv204.client.Main add gmail mypassword
java -cp client/src/main/java com.pv204.client.Main get gmail
java -cp client/src/main/java com.pv204.client.Main change-pin 1234 5678