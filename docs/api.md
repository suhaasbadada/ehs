## API Reference

This document provides a compact reference for the HTTP API exposed by the EHS project. It is intended as a developer-facing summary: base URL, authentication, main endpoints, request/response shapes, and examples.

### Contract (short)
- Base URL: the server address where the app is hosted (for local dev often `http://localhost:8000`).
- Auth: session / token-based authentication (see Authentication section).
- Input: JSON request bodies where documented.
- Output: JSON responses with HTTP status codes. Errors use an `error` field containing a short message.

### Authentication
- Endpoints under `/auth` manage session tokens.
- Typical flows: login -> receive token (or session cookie) -> use token in `Authorization: Bearer <token>` header.
- See implementation in `src/auth/session_manager.py` and `src/api/routes.py`.

### Common headers
- Content-Type: `application/json`
- Authorization: `Bearer <token>` (when required)

### Endpoints (summary)

- POST /auth/login
  - Purpose: authenticate user and obtain a token/session
  - Request body: {"username": "...", "password": "..."}
  - Response 200: {"token": "...", "expires_in": 3600}
  - Response 401: {"error": "invalid credentials"}

- POST /auth/logout
  - Purpose: invalidate current session/token
  - Auth required
  - Response 204: No content

- GET /patients
  - Purpose: list patients (supports pagination and filters)
  - Query params (optional): `page`, `per_page`, `q` (search)
  - Response 200: {"items": [<Patient>], "total": 123}

- POST /patients
  - Purpose: create a new patient record
  - Auth/permission required (see `src/auth/permissions.py`)
  - Request body (example):
    {
      "first_name": "Jane",
      "last_name": "Doe",
      "dob": "1980-01-01",
      "medical_id": "MD-0001"
    }
  - Response 201: created patient object

- GET /patients/{id}
  - Purpose: retrieve a patient by id
  - Response 200: patient object
  - Response 404: {"error": "not found"}

- PUT /patients/{id}
  - Purpose: update patient record
  - Auth/permission required
  - Response 200: updated patient

- DELETE /patients/{id}
  - Purpose: delete patient record (soft or hard delete depending on config)
  - Auth/permission required
  - Response 204: No content

- GET /devices
  - Purpose: list registered medical devices
  - Response 200: {"items": [<Device>], "total": N}

- POST /devices
  - Purpose: register a new device
  - Auth/permission required (likely admin)
  - Response 201: created device

- GET /audit/logs
  - Purpose: retrieve audit logs (restricted access)
  - Query params: `since`, `until`, `level`, `user_id`
  - Auth: admin/audit role required

### Schemas / shapes (reference)
- Patient (example shape)
  - id: string
  - first_name: string
  - last_name: string
  - dob: date string (YYYY-MM-DD)
  - medical_id: string

- Device (example shape)
  - id: string
  - name: string
  - model: string
  - serial_number: string
  - status: string (registered/active/inactive)

For full, canonical schemas see `src/api/schemas.py`.

### Error handling
- Standard response: HTTP status + JSON body `{ "error": "human readable message" }`.
- Validation errors may include a `details` or `errors` array with field-level messages.

### Examples

Login and use a token (curl examples):

```bash
# Login
curl -X POST -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"secret"}' \
  http://localhost:8000/auth/login

# Use token (replace <token>)
curl -H "Authorization: Bearer <token>" http://localhost:8000/patients
```

Create a patient:

```bash
curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer <token>" \
  -d '{"first_name":"John","last_name":"Smith","dob":"1975-05-05","medical_id":"MD-100"}' \
  http://localhost:8000/patients
```

### Notes & next steps
- This file is a concise reference. For precise routes and parameter names, verify `src/api/routes.py` and `src/api/schemas.py`.
- If you want this converted into an OpenAPI / swagger spec, I can generate an `openapi.yaml` or integrate auto-generation from the code.