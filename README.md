# Public Key Infrastructure

Public Key Infrastructure system to manage digital certificates, provides tools for creating, managing, and distributing certificates securely.

## Requirements
- [Docker](https://docs.docker.com/engine/install/)
- [Docker Compose](https://docs.docker.com/compose/install/)

## Running the Project
- Rename, or create a copy of **.env.example** called **.env** with your own data

<br/>

- `docker compose up -d` to start all containers
- `docker compose down` to remove all containers
  - use the `-v` flag to remove the volumes as well

## Routes

- **Frontend** at **http://localhost:4200**
- **Backend** at **http://localhost:8080**
- **pgAdmin** at **http://localhost:5050**