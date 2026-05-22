# EAP Secrets API Documentation

This document describes the RESTful API endpoints for managing EAP (Extensible Authentication Protocol) users in strongMan.

## Authentication

All API endpoints require authentication. You must be logged in to the strongMan application to use these APIs.

## Base URL

```
/eap_secrets/api/
```

## Endpoints

### 1. Create EAP User

Create a new EAP user with username and password.

**Endpoint:** `POST /eap_secrets/api/create`

**Request Body:**
```json
{
  "username": "testuser",
  "password": "securepassword123"
}
```

**Request Rules:**
- `username`: Required, alphanumeric characters, underscore and hyphen only (regex: `^[0-9a-zA-Z_\-]+$`)
- `password`: Required, max 50 characters

**Success Response (201 Created):**
```json
{
  "success": true,
  "message": "EAP user created successfully",
  "data": {
    "username": "testuser"
  }
}
```

**Error Responses:**

- **400 Bad Request** - Missing or invalid parameters
```json
{
  "success": false,
  "error": "Username and password are required"
}
```

- **409 Conflict** - User already exists
```json
{
  "success": false,
  "error": "EAP user \"testuser\" already exists"
}
```

**cURL Example:**
```bash
curl -X POST http://localhost:1515/eap_secrets/api/create \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"username":"testuser","password":"securepassword123"}'
```

---

### 2. Delete EAP User

Delete an existing EAP user by username.

**Endpoint:** `DELETE /eap_secrets/api/{username}/delete`

**URL Parameters:**
- `username`: The username of the EAP user to delete

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "EAP user \"testuser\" deleted successfully"
}
```

**Error Response (404 Not Found):**
```json
{
  "success": false,
  "error": "EAP user \"testuser\" not found"
}
```

**cURL Example:**
```bash
curl -X DELETE http://localhost:1515/eap_secrets/api/testuser/delete \
  -b cookies.txt
```

---

### 3. List All EAP Users

Retrieve a list of all EAP users (passwords are not included).

**Endpoint:** `GET /eap_secrets/api/`

**Success Response (200 OK):**
```json
{
  "success": true,
  "count": 2,
  "users": [
    {"username": "user1"},
    {"username": "user2"}
  ]
}
```

**cURL Example:**
```bash
curl -X GET http://localhost:1515/eap_secrets/api/ \
  -b cookies.txt
```

---

### 4. Get EAP User Details

Retrieve details of a specific EAP user (password is not included).

**Endpoint:** `GET /eap_secrets/api/{username}`

**URL Parameters:**
- `username`: The username of the EAP user

**Success Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "username": "testuser",
    "type": "EAP"
  }
}
```

**Error Response (404 Not Found):**
```json
{
  "success": false,
  "error": "EAP user \"testuser\" not found"
}
```

**cURL Example:**
```bash
curl -X GET http://localhost:1515/eap_secrets/api/testuser \
  -b cookies.txt
```

---

## Authentication with cURL

To authenticate with cURL, first login and save the session cookie:

```bash
# Login and save cookies
curl -X POST http://localhost:1515/login/ \
  -d "username=John&password=Lennon@1940" \
  -c cookies.txt

# Then use the cookies for API requests
curl -X GET http://localhost:1515/eap_secrets/api/ \
  -b cookies.txt
```

---

## Error Handling

All endpoints return JSON responses with the following structure:

**Success:**
```json
{
  "success": true,
  "message": "...",
  "data": {...}
}
```

**Error:**
```json
{
  "success": false,
  "error": "Error message"
}
```

**HTTP Status Codes:**
- `200 OK` - Request successful
- `201 Created` - Resource created successfully
- `400 Bad Request` - Invalid request parameters
- `404 Not Found` - Resource not found
- `409 Conflict` - Resource already exists
- `500 Internal Server Error` - Server error

---

## Security Notes

1. All API endpoints require authentication via Django session
2. Passwords are encrypted before storage using `EncryptedCharField`
3. Passwords are salted with a random 24-byte salt
4. API responses never include password data
5. CSRF protection is disabled for API endpoints to allow programmatic access

---

## Complete Usage Example

```bash
# 1. Login
curl -X POST http://localhost:1515/login/ \
  -d "username=John&password=Lennon@1940" \
  -c cookies.txt

# 2. Create a new EAP user
curl -X POST http://localhost:1515/eap_secrets/api/create \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"username":"vpnuser1","password":"MySecurePass123"}'

# 3. List all EAP users
curl -X GET http://localhost:1515/eap_secrets/api/ \
  -b cookies.txt

# 4. Get specific user details
curl -X GET http://localhost:1515/eap_secrets/api/vpnuser1 \
  -b cookies.txt

# 5. Delete the user
curl -X DELETE http://localhost:1515/eap_secrets/api/vpnuser1/delete \
  -b cookies.txt
```
