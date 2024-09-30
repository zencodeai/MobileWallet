# Mobile Wallet Prototype

## Table of Contents

- [Project Overview](#project-overview)
- [Features](#features)
- [Technologies Used](#technologies-used)
- [Folder Structure](#folder-structure)
- [TODO](#todo)

---

## Project Overview

This project is a **Mobile Wallet Prototype** designed to demonstrate the applicability of mobile threat detection and remediation products for protecting critical assets and operations. The wallet is a cross platform native module that, once protected, acts as the root of trust of the application and device.


## Features

- User registration (backend)
- Wallet provisioning
- Wallet funding
- Wallet defunding
- P2P transaction
- Online transactions
- Balance check and transaction history
- Transaction processor backend with API-based communication

## Technologies Used

- **Frontend (Mobile):**
  - C/C++/Kotlin/Swift/Objective-C
  - Flutter/Dart
  - SQLite

- **Backend:**
  - Python (FastAPI)
  - SQLite

- **Notes:**
    - Not much effort has been put in the Flutter version as Flutter is not well supported by mobile threat defense frameworks and is not really cross-platform in complex designs.

---

## Folder Structure

The folder structure below outlines the key components of both the mobile front-end and backend, along with their roles:

| Folder/File        | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| `Backend`     | Provisioning and transactions processing backend       |
| `Backend/backend_admin` | Backend administration tool (Python).                     |
| `Backend/backend_app`    | Backend application (FastAPI, Python) |
| `OBPClient`     | Proof of Concept about exploring OpenBanking API has a possible backend for the prototype.                       |
| `SecureKernel`      | The native wallet component.                                |
| `SecureKernel/ext`   | External dependencies.                              |
| `SecureKernel/inc`          | Generated module's constants.         |
| `SecureKernel/include`       | Module's API.                                           |
| `SecureKernel/sk_app` | Mobile applications.         |
| `SecureKernel/.../sk_app_android` | Android application. |
| `SecureKernel/.../sk_app_ios` | iOS application. |
| `SecureKernel/sk_plugin` | Flutter/Dart implementation attempt.                             |
| `SecureKernel/src` | Wallet's source code (C++).   |
| `SecureKernel/test`    | Unit tests.    |
| `SecureKernel/utils`     | Various supporting scripts.             |
| `SecureKernel/wrapper`  | Wrapper for E2E tests.                        |
| `Utils`     | Scripts for E2E testing                       |
| `WalletUIDesign`     | Flutter concept for the wallet UI design        |

---

## TODO

- User authentication and authorization.
- Secure link btw client and backend (platform level).
- Implement UI
- Implement proper business logic layer.
- Check integration of Post-Quantum safe algorithms.