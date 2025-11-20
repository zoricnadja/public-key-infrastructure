# Public Key Infrastructure

Project for the course Informaciona bezbednost (Information Security), implementing a Public Key Infrastructure (PKI) system to manage digital certificates and secure communication.

## Table of Contents
- [Project Overview](#project-overview)
- [Features & User Roles](#features--user-roles)
- [System Functionalities](#system-functionalities)
- [Technology Stack](#technology-stack)
- [Technical Installation & Run](#technical-installation--run)
- [Security Requirements](#security-requirements)
- [Advanced Details](#advanced-details)

---

## Project Overview

This PKI system enables secure creation, issuance, management, and storage of digital certificates for organizations and end-users. It supports Root, Intermediate, and End-Entity certificate operations, compliant with X.509 standards, ensuring confidentiality and role-based management. The project is a fork of [DamjanVincic/public-key-infrastructure](https://github.com/DamjanVincic/public-key-infrastructure).

---

## Features & User Roles

### User Roles

- **Administrator**
  - Add CA users and manage their certificates for systems/servers.
  - Issue all certificate types (Root, Intermediate, End-Entity).
  - View, manage, download, and revoke any certificate in the system.
  - Utilize any certificate and key from any chain.

- **CA User**
  - Issue Intermediate and End-Entity certificates for their organization.
  - Use their CA certificate or any certificate in their chain.
  - View and download only certificates in their chain.
  - Create and use templates for organization certificates.

- **Regular User**
  - Register with organization, upload CSR and keys, or auto-generate key/cert.
  - Choose issuing CA, download certificate and key, manage and revoke own certificates.

---

## System Functionalities

- **Certificate Issuance & Management**
  - Create Root (self-signed), Intermediate, and End-Entity certificates.
  - Upload and process Certificate Signing Requests (CSR).
  - In-app generation of keys and certificates.
  - X.509 attribute and extensions support.
  - Secure storage of certificates and encrypted private keys in the database.

- **Certificate Revocation**
  - Users can revoke certificates by reason, in line with X.509.
  - CRL Distribution Point for revocation status.

- **Authentication & Access Control**
  - Login/registration only for regular users.
  - Authentication via short-lived access token and long-lived refresh token (JWT).
  - Role-based access enforced throughout.

---

## Technology Stack

- **Backend:** Java (Spring Boot)
- **Frontend:** Angular (TypeScript, HTML, CSS)
- **Database:** PostgreSQL
- **Security:** Bouncy Castle, Java Keystore, PKCS12
- **DevOps:** Docker, Docker Compose
- **Admin Panel:** pgAdmin

---

## Technical Installation & Run


### Requirements
- [Docker](https://docs.docker.com/engine/install/)
- [Docker Compose](https://docs.docker.com/compose/install/)

### Running the Project
- Rename, or create a copy of **.env.example** called **.env** with your own data


 Start all services:
   ```bash
   docker compose up -d
   ```

 Stop and clean up:
   ```bash
   docker compose down        # add -v to remove volumes as well
   ```


### Routes

- **Frontend** at **http://localhost:4200**
- **Backend** at **http://localhost:8080**
- **pgAdmin** at **http://localhost:5050**


## Security Requirements

- Registration only for regular users, with email confirmation and password strength enforcement.
- All communications over HTTPS (PKI-generated certs can be used).
- Private keys stored encrypted per organization/master key 
- JWT token authentication; access/refresh tokens
- Revocation support: CRL and UI/API validation.

---

## Advanced Details

- CSR upload and in-app generation flows supported.
- All certificate downloads packaged as PKCS12 or JKS.
- Role-based policy enforced at all endpoints.
