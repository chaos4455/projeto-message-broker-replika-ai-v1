
*   The API will be available at `https://localhost:8777` (or your machine's IP).
*   Since it uses a self-signed certificate, you'll likely need to tell your browser or `curl` client to ignore certificate errors (e.g., using the `-k` flag with `curl`).
*   Press `Ctrl+C` to stop the server gracefully.

---

## 💻 API Usage & Endpoints

**Base URL:** `https://localhost:8777` (default)
**Default Port:** `8777`
**Protocol:** `HTTPS` (Self-signed cert by default)

**General Notes:**

*   All request bodies expecting data should use `Content-Type: application/json`.
*   Authenticated endpoints require an `Authorization: Bearer <your_access_token>` header, where `<your_access_token>` is obtained from `/login`.
*   Use `curl -k` to bypass self-signed certificate verification warnings.

---

### 🔑 Authentication

#### `POST /login`

*   **Description:** Authenticates a user.
*   **Auth:** None required.
*   **Rate Limit:** 10 per minute.
*   **Request Body:**
    ```json
    {
        "username": "admin",
        "password": "admin"
    }
    ```
*   **Success (200 OK):**
    ```json
    {
        "access_token": "eyJ...",
        "refresh_token": "eyJ..."
    }
    ```
*   **Errors:** `400` (Bad Payload), `401` (Invalid Credentials).
*   **`curl` Example:**
    ```bash
    curl -k -X POST https://localhost:8777/login \
      -H "Content-Type: application/json" \
      -d '{"username": "admin", "password": "admin"}'
    ```

#### `POST /refresh`

*   **Description:** Generates a new access token using a refresh token.
*   **Auth:** JWT Refresh Token Required (`Authorization: Bearer <refresh_token>`).
*   **Request Body:** None.
*   **Success (200 OK):**
    ```json
    {
        "access_token": "eyJ..." // New access token
    }
    ```
*   **Errors:** `401` (Invalid/Expired Refresh Token).
*   **`curl` Example:**
    ```bash
    curl -k -X POST https://localhost:8777/refresh \
      -H "Authorization: Bearer <your_refresh_token>"
    ```

---

### 📥 Queue Management

#### `POST /queues`

*   **Description:** Creates a new queue.
*   **Auth:** JWT Access Token Required.
*   **Rate Limit:** 60 per minute.
*   **Request Body:**
    ```json
    {
        "name": "my-processing-queue"
        // Name: 1-255 chars, alphanumeric, underscores, hyphens
    }
    ```
*   **Success (201 Created):**
    ```json
    {
        "msg": "Queue created",
        "name": "my-processing-queue",
        "id": 1
    }
    ```
*   **Errors:** `400` (Invalid Name), `401` (Unauthorized), `409` (Name Exists), `500` (DB Error).
*   **`curl` Example:**
    ```bash
    curl -k -X POST https://localhost:8777/queues \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer <your_access_token>" \
      -d '{"name": "my-processing-queue"}'
    ```

#### `GET /queues`

*   **Description:** Lists all queues.
*   **Auth:** JWT Access Token Required.
*   **Rate Limit:** 100 per minute.
*   **Success (200 OK):**
    ```json
    [
        {
            "id": 1,
            "name": "my-processing-queue",
            "created_at": "2025-04-02T23:10:00Z"
        },
        {
            "id": 2,
            "name": "email-queue",
            "created_at": "2025-04-02T23:15:00Z"
        }
    ]
    ```
*   **Errors:** `401` (Unauthorized), `500` (DB Error).
*   **`curl` Example:**
    ```bash
    curl -k -X GET https://localhost:8777/queues \
      -H "Authorization: Bearer <your_access_token>"
    ```

#### `GET /queues/{queue_name}`

*   **Description:** Gets details of a specific queue.
*   **Auth:** JWT Access Token Required.
*   **Rate Limit:** 100 per minute.
*   **URL Params:** `queue_name` (string).
*   **Success (200 OK):**
    ```json
    {
        "id": 1,
        "name": "my-processing-queue",
        "created_at": "2025-04-02T23:10:00Z",
        "pending_messages": 55 // Count of messages with 'pending' status
    }
    ```
*   **Errors:** `401` (Unauthorized), `404` (Not Found), `500` (DB Error).
*   **`curl` Example:**
    ```bash
    curl -k -X GET https://localhost:8777/queues/my-processing-queue \
      -H "Authorization: Bearer <your_access_token>"
    ```

#### `DELETE /queues/{queue_name}`

*   **Description:** Deletes a queue and all its messages.
*   **Auth:** JWT Access Token Required.
*   **Rate Limit:** 30 per minute.
*   **URL Params:** `queue_name` (string).
*   **Success (200 OK):**
    ```json
    {
        "msg": "Queue 'my-processing-queue' deleted"
    }
    ```
*   **Errors:** `401` (Unauthorized), `404` (Not Found), `500` (DB Error).
*   **`curl` Example:**
    ```bash
    curl -k -X DELETE https://localhost:8777/queues/my-processing-queue \
      -H "Authorization: Bearer <your_access_token>"
    ```

---

### ✉️ Message Handling

#### `POST /queues/{queue_name}/messages`

*   **Description:** Publishes a message to a specific queue.
*   **Auth:** JWT Access Token Required.
*   **Rate Limit:** 500 per minute.
*   **URL Params:** `queue_name` (string).
*   **Request Body:**
    ```json
    {
        "content": { "user_id": 123, "action": "update_profile" } // Or string, list
    }
    ```
*   **Success (201 Created):**
    ```json
    {
        "msg": "Message published",
        "message_id": 101
    }
    ```
*   **Errors:** `400` (Invalid Payload), `401` (Unauthorized), `404` (Queue Not Found), `500` (DB Error).
*   **`curl` Example:**
    ```bash
    curl -k -X POST https://localhost:8777/queues/my-processing-queue/messages \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer <your_access_token>" \
      -d '{"content": {"task": "send_report", "report_id": 5}}'
    ```

#### `GET /queues/{queue_name}/messages`

*   **Description:** Consumes the oldest pending message from a queue. Marks it 'processing'.
*   **Auth:** JWT Access Token Required.
*   **Rate Limit:** 200 per minute.
*   **URL Params:** `queue_name` (string).
*   **Success (200 OK):**
    ```json
    {
        "message_id": 101,
        "queue": "my-processing-queue",
        "content": { "task": "send_report", "report_id": 5 },
        "status": "processing",
        "retrieved_at": "2025-04-02T23:20:00Z"
    }
    ```
*   **Success (204 No Content):** If the queue is empty (no pending messages). Body is empty.
*   **Errors:** `401` (Unauthorized), `404` (Queue Not Found), `500` (DB Error).
*   **`curl` Example:**
    ```bash
    curl -k -X GET https://localhost:8777/queues/my-processing-queue/messages \
      -H "Authorization: Bearer <your_access_token>"
    ```
    **Note:** You MUST call `/ack` or `/nack` after processing this message.

#### `POST /messages/{message_id}/ack`

*   **Description:** Acknowledges successful processing of a consumed message. Marks it 'processed'.
*   **Auth:** JWT Access Token Required.
*   **Rate Limit:** 200 per minute.
*   **URL Params:** `message_id` (integer).
*   **Request Body:** None.
*   **Success (200 OK):**
    ```json
    {
        "msg": "Message 101 acknowledged"
    }
    ```
*   **Errors:** `401` (Unauthorized), `403` (Forbidden - Not the consumer), `404` (Not Found), `409` (Conflict - Message not 'processing'), `500` (DB Error).
*   **`curl` Example:**
    ```bash
    curl -k -X POST https://localhost:8777/messages/101/ack \
      -H "Authorization: Bearer <your_access_token>"
    ```

#### `POST /messages/{message_id}/nack`

*   **Description:** Negatively acknowledges a consumed message (processing failed). Marks it 'failed'.
*   **Auth:** JWT Access Token Required.
*   **Rate Limit:** 200 per minute.
*   **URL Params:** `message_id` (integer).
*   **Request Body:** None.
*   **Success (200 OK):**
    ```json
    {
        "msg": "Message 101 marked as failed (NACK)"
    }
    ```
*   **Errors:** `401` (Unauthorized), `403` (Forbidden - Not the consumer), `404` (Not Found), `409` (Conflict - Message not 'processing'), `500` (DB Error).
*   **`curl` Example:**
    ```bash
    curl -k -X POST https://localhost:8777/messages/101/nack \
      -H "Authorization: Bearer <your_access_token>"
    ```

---

### 📊 Statistics

#### `GET /stats`

*   **Description:** Retrieves broker and system statistics.
*   **Auth:** JWT Access Token Required.
*   **Rate Limit:** 30 per minute.
*   **Success (200 OK):** (See example in previous response or the code comments for the full structure)
*   **Errors:** `401` (Unauthorized), `500` (Stats Collection Error).
*   **`curl` Example:**
    ```bash
    curl -k -X GET https://localhost:8777/stats \
      -H "Authorization: Bearer <your_access_token>"
    ```

---

### 📄 Log Viewing

#### `GET /logs`

*   **Description:** Lists available JSON log files.
*   **Auth:** JWT Access Token Required.
*   **Rate Limit:** 10 per minute.
*   **Success (200 OK):**
    ```json
    {
        "log_files": [
            "broker_log_20250402_231500_abcdef12.json",
            "broker_log_20250402_231000_fedcba98.json"
        ]
    }
    ```
*   **Errors:** `401` (Unauthorized), `500` (Directory Read Error).
*   **`curl` Example:**
    ```bash
    curl -k -X GET https://localhost:8777/logs \
      -H "Authorization: Bearer <your_access_token>"
    ```

#### `GET /logs/{filename}`

*   **Description:** Retrieves content of a specific log file.
*   **Auth:** JWT Access Token Required.
*   **Rate Limit:** 60 per minute.
*   **URL Params:** `filename` (string - exact log filename).
*   **Query Params (Optional):** `start` (int), `end` (int), `tail` (int).
*   **Success (200 OK):** Returns a JSON array of log entry objects. (See example structure in code comments or previous response).
*   **Errors:** `400` (Invalid Filename), `401` (Unauthorized), `404` (Not Found), `500` (File Read Error).
*   **`curl` Example (Full File):**
    ```bash
    curl -k -X GET "https://localhost:8777/logs/broker_log_20250402_231500_abcdef12.json" \
      -H "Authorization: Bearer <your_access_token>"
    ```
*   **`curl` Example (Tail):**
    ```bash
    curl -k -X GET "https://localhost:8777/logs/broker_log_20250402_231500_abcdef12.json?tail=50" \
      -H "Authorization: Bearer <your_access_token>"
    ```
*   **`curl` Example (Range):**
    ```bash
    curl -k -X GET "https://localhost:8777/logs/broker_log_20250402_231500_abcdef12.json?start=100&end=150" \
      -H "Authorization: Bearer <your_access_token>"
    ```

---

## 🍇 GraphQL API

*   **Endpoint:** `POST /graphql` (or `GET /graphql` for GraphiQL interface in browser)
*   **Auth:** JWT Access Token Required.
*   **Description:** Query queue and message data using the GraphQL query language.
*   **Interface:** Accessing `https://localhost:8777/graphql` in a browser usually loads the GraphiQL IDE for exploration.
*   **Example Query:**
    ```graphql
    query GetQueueAndMessages {
      queueByName(name: "my-processing-queue") {
        id
        name
        createdAt
      }
      messagesInQueue(queueName: "my-processing-queue", status: "pending", limit: 10) {
        id
        status
        createdAt
        content
      }
    }
    ```
*   **`curl` Example (POST):**
    ```bash
    curl -k -X POST https://localhost:8777/graphql \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer <your_access_token>" \
      -d '{"query": "query { allQueues { edges { node { id name } } } }"}'
      # Remember to properly escape quotes if needed in your shell
    ```

---

## 📡 Server-Sent Events (SSE)

*   **Endpoint:** `GET /stream`
*   **Auth:** None required for the connection itself.
*   **Description:** Establishes a persistent connection for receiving real-time events.
*   **Events Pushed:**
    *   `new_message`: When a message is published.
    *   `message_acked`: When a message is successfully acknowledged.
    *   `message_nacked`: When a message is negatively acknowledged (failed).
*   **Event Data Format:**
    ```json
    // Example: data field sent by the server
    {
        "queue": "my-processing-queue", // Which queue the event relates to
        "message_id": 102,
        "event": "new_message" // Type of event
    }
    ```
*   **Client Usage:** Use the `EventSource` API in JavaScript or equivalent library in other languages to connect to `https://localhost:8777/stream`. Parse the `event.data` JSON string to act on notifications. See `doc_server.py` example for client-side filtering ideas.

---

## 📄 Logging

*   **Location:** Logs are stored in the `./logs_v3/` directory by default.
*   **Format:** Each log file is named `broker_log_YYYYMMDD_HHMMSS_hash.json`.
*   **Structure:** Each line in the JSON file represents a log entry with fields like `timestamp`, `level`, `name`, `pid`, `thread`, `message`, `icon_type`, `exception` (if any), `traceback` (if any), and `extra_data`.
*   **Console Output:** Colored, human-readable logs are also printed to the standard output.

---

## 🛡️ Security Considerations

*   **JWT Secrets:** **NEVER** commit your `FLASK_SECRET_KEY` or `JWT_SECRET_KEY` to version control. Use environment variables or a secure secrets management system in production.
*   **Password Hashing:** The `/login` endpoint currently uses plain text comparison (`'admin' == 'admin'`). **THIS IS HIGHLY INSECURE.** Implement strong password hashing (e.g., using `passlib` with bcrypt) before any real-world use.
*   **HTTPS:** The broker uses HTTPS with a self-signed certificate. For production, obtain a valid certificate from a Certificate Authority (CA) (e.g., Let's Encrypt).
*   **Input Validation:** Pydantic models provide good validation, preventing many injection-style attacks on request payloads.
*   **Rate Limiting:** Helps prevent brute-force attacks and resource exhaustion. Adjust limits based on expected usage.
*   **CORS:** Configure `ALLOWED_ORIGINS` strictly in production to only allow requests from your known frontend applications. Avoid `*`.
*   **Dependencies:** Keep all dependencies up-to-date to patch security vulnerabilities (`pip list --outdated`, `pip install -U <package>`).
*   **Redis Security:** Secure your Redis instance (password protection, network isolation).

---

## 📝 Version Notes (v0.3.1-sqlite)

*   **Database Backend:** Changed from PostgreSQL (in conceptual previous versions) to **SQLite** using `aiosqlite` for simplified setup.
*   **Async Core:** Fully asynchronous operation using `asyncio`, `SQLAlchemy`, and `Uvicorn`.
*   **ORM:** Uses SQLAlchemy ORM for database interaction.
*   **Features Added/Refined:**
    *   Server-Sent Events (SSE) via Redis for real-time updates.
    *   GraphQL API endpoint (`/graphql`) for flexible querying.
    *   Enhanced Statistics (`/stats`) including psutil system metrics.
    *   Log viewing API (`/logs`, `/logs/{filename}`).
    *   Pydantic-based request validation.
    *   Flask-Limiter integration for rate limiting.
    *   Self-signed certificate generation.
    *   Structured JSON logging alongside colored console logs.
    *   Refined error handling and response codes.
*   **Limitations:**
    *   SQLite's concurrency handling is less sophisticated than PostgreSQL's. High-contention scenarios on message consumption *might* experience more blocking or rare race conditions compared to using `SKIP LOCKED` in PostgreSQL.
    *   No built-in Dead Letter Queue (DLQ) or automatic retry mechanism for failed messages (`/nack` simply marks them 'failed').
    *   Simple user authentication (placeholder 'admin'/'admin').

---

**Signed:**

*Eias Andrade*
*Replika AI Solutions*
*2025-04-02 23:16 Hours*