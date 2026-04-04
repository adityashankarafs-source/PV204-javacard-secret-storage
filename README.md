# PV204 JavaCard Secret Storage

## Team Members
- Aditya Shankar
- Ujjawal Kumar
- Khaled Kamal Hegazy

## Project Description
This project implements a secure secret storage system using JavaCard technology.

The system supports:
- storing secrets securely on a smart card
- listing stored secret names
- retrieving secrets after PIN verification
- changing the PIN securely
- secure channel communication with replay protection
- runtime key provisioning

## Repository Structure
- `applet/` — JavaCard applet code
- `client/` — client application
- `docs/` — architecture and project documentation
- `tests/` — test-related files
- `libs/` — project libraries
- `libs-sdks/` — local JavaCard SDK folder (not necessarily tracked in Git)

## Technology Stack
- JavaCard
- Java
- jCardSim
- Gradle

## Current Status
Implemented so far:
- applet functionality for secret storage
- secure channel support
- PIN verification flow
- runtime key provisioning
- test coverage for core applet flows
- client CLI structure and command flow
- project documentation and demo/test scenarios

## Local Setup

### Prerequisites
- Java installed
- Gradle wrapper available in the project
- JavaCard SDK available locally

### JavaCard SDK Setup
The project expects the following folder to exist locally:

```text
libs-sdks/jc310b43_kit