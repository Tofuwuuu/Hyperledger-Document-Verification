# CVSU Alumni Document Verification

My capstone for Cavite State University (CVSU) Carmona. Alumni keep a profile and upload documents. An admin approves them, and the SHA-256 hash goes onto a Hyperledger Fabric ledger. Anyone can later upload a file and check it hasn't been changed.

![Admin document verification with a file preview and approve or reject actions](docs/screenshots/admin-document-verification.png)

https://hyperledger-document-verification.vercel.app/ is a UI preview only. The screens load, but login is off and nothing is sent to an API (see `frontend/README.md`). The full app runs locally.

## Who does what

- Anyone can open `/verify` without logging in, upload a file and compare its hash to the ledger, optionally against a specific document id.
- Alumni register, edit their profile, and once an admin verifies the account, upload documents, request official documents, sign up for events and read notifications.
- Admins approve or reject accounts, review uploads, and on approval try to write the hash to Fabric. They also run events.

QR check-in, role management and meetings have screens but don't work yet.

Only hashes and a little metadata go on the ledger. Files stay in MongoDB and `backend/uploads/`.

## Things to know before reading the code

- The Fabric network is a single-org dev network: `Org1MSP`, channel `alumni-channel`, chaincode `final-smart-contract`. The gateway signs as the Org1 admin. It's not a multi-org consortium.
- Compose starts the API with `USE_REAL_BLOCKCHAIN=false`, so approvals go to the in-memory mock ledger in `backend/app/blockchain/fabric.py`.
- If the chain write fails or times out, approval still goes through in MongoDB with a `mongo-fallback-…` transaction id (`backend/app/api/endpoints/admin.py`).

```text
React (Vite)  --HTTP /api/v1-->  FastAPI  --MongoDB-->  users, documents, events
                                    |
                                    | USE_REAL_BLOCKCHAIN=true
                                    v
                              fabric-gateway (Express)
                                    |  @hyperledger/fabric-gateway (gRPC)
                                    v
                         peer0.org1.example.com
                         chaincode final-smart-contract
                         StoreDocument / VerifyDocument / VerifyHash / GetDocumentHistory
```

Verify and approve both go through `BlockchainManager` (`backend/app/services/blockchain_manager.py`) to `FabricClient` (`backend/app/clients/fabric_client.py`), which calls `fabric-gateway/src/server.js` over HTTP. More in [docs/architecture.md](docs/architecture.md).

React 18, Vite, Tailwind and Chakra UI on the front. FastAPI, Motor and Pydantic on the back. The gateway is Express with `@hyperledger/fabric-gateway`, and the chaincode is JavaScript.

## Run it

You need Docker, Node 18+ and Python 3.11. The Fabric scripts are PowerShell.

```bash
export SECRET_KEY=$(openssl rand -hex 32)
docker network create cvsu_alumni_blockchain_network   # once
docker compose up -d --build
cd frontend && npm install --legacy-peer-deps && npm run dev
```

API docs at http://127.0.0.1:8000/docs, frontend at http://localhost:5173, Mongo Express at http://localhost:8081. The API won't start without `SECRET_KEY`. The Compose frontend is behind the `docker-frontend` profile, which is why Vite runs on the host.

Outside Compose, copy `frontend/.env.example` and `backend/.env.example` to `.env` first. From the root, `npm run install-all` then `npm start` runs the API and Vite together.

To use a real peer, start Fabric, deploy the chaincode and set `USE_REAL_BLOCKCHAIN=true`. Steps are in [docs/local-setup.md](docs/local-setup.md).

`fabric-samples` is in `.gitmodules` but not needed. The `blockchain-explorer` nginx service in Compose has no directory behind it, so it serves nothing.

## Screens

![Login page with email and password fields](docs/screenshots/login.png)
![Alumni dashboard with profile summary and quick actions](docs/screenshots/student-dashboard.png)
![Upload document form for file, document type, and description](docs/screenshots/upload-document.png)
![My documents list](docs/screenshots/my-document.png)
![Admin dashboard with summary cards and quick actions](docs/screenshots/admin-dashboard.png)

Captured from the local app.

## More

- [docs/architecture.md](docs/architecture.md): request path and chaincode
- [docs/local-setup.md](docs/local-setup.md): env files and Fabric startup
- [docs/system-implementation.md](docs/system-implementation.md): module notes
- [fabric-network/README.md](fabric-network/README.md): peer, orderer and chaincode deploy

[MIT](LICENSE)
