# doc_server.py
import os
from flask import Flask, Response

# --- Configuration ---
DOC_SERVER_PORT = 8112
API_BASE_URL = "https://localhost:8777" # The actual base URL of your running API

# --- Flask App ---
app = Flask(__name__)

# --- HTML Content with Embedded CSS ---
# Note: Using f-string for easy embedding of API_BASE_URL
HTML_CONTENT = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🚀 Message Broker API Documentation</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --primary-color: #6a11cb;
            --secondary-color: #2575fc;
            --card-bg: rgba(255, 255, 255, 0.95);
            --text-color: #333;
            --heading-color: #fff;
            --code-bg: #f0f2f5;
            --code-text: #333;
            --shadow-light: rgba(0, 0, 0, 0.1);
            --shadow-medium: rgba(0, 0, 0, 0.15);
            --border-radius: 8px;
            --success-color: #28a745;
            --error-color: #dc3545;
            --warning-color: #ffc107;
            --info-color: #17a2b8;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Poppins', sans-serif;
            line-height: 1.7;
            color: var(--text-color);
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            background-attachment: fixed;
            padding: 20px;
            font-size: 16px;
        }}

        .container {{
            max-width: 1000px;
            margin: 20px auto;
            background-color: rgba(255, 255, 255, 0.85);
            padding: 30px 40px;
            border-radius: var(--border-radius);
            box-shadow: 0 10px 30px var(--shadow-medium);
        }}

        h1, h2, h3 {{
            margin-bottom: 0.8em;
            color: var(--primary-color);
            font-weight: 600;
        }}

        h1 {{
            font-size: 2.5em;
            text-align: center;
            margin-bottom: 1em;
            color: var(--secondary-color); /* Different color for main title */
            text-shadow: 1px 1px 2px var(--shadow-light);
        }}

        h2 {{
            font-size: 1.8em;
            border-bottom: 2px solid var(--secondary-color);
            padding-bottom: 0.3em;
            margin-top: 1.8em;
        }}

        h3 {{
            font-size: 1.3em;
            margin-top: 1.5em;
            color: var(--primary-color);
        }}

        p {{
            margin-bottom: 1em;
        }}

        a {{
            color: var(--secondary-color);
            text-decoration: none;
        }}

        a:hover {{
            text-decoration: underline;
        }}

        .card {{
            background-color: var(--card-bg);
            border-radius: var(--border-radius);
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 5px 15px var(--shadow-light);
            border-left: 5px solid var(--primary-color);
            transition: transform 0.2s ease-in-out, box-shadow 0.2s ease-in-out;
        }}

        .card:hover {{
            transform: translateY(-3px);
            box-shadow: 0 8px 20px var(--shadow-medium);
        }}

        .endpoint-header {{
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }}

        .method {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 5px;
            color: #fff;
            font-weight: 700;
            font-size: 0.9em;
            text-transform: uppercase;
        }}

        .method-get {{ background-color: #2575fc; }}
        .method-post {{ background-color: #28a745; }}
        .method-delete {{ background-color: #dc3545; }}
        .method-put {{ background-color: #fd7e14; }} /* Example if needed */
        .method-patch {{ background-color: #ffc107; }} /* Example if needed */

        .endpoint-path {{
            font-family: 'Courier New', Courier, monospace;
            font-weight: 600;
            font-size: 1.1em;
            color: var(--primary-color);
            word-break: break-all;
            background-color: var(--code-bg);
            padding: 3px 6px;
            border-radius: 4px;
        }}

        pre {{
            background-color: var(--code-bg);
            color: var(--code-text);
            padding: 15px;
            border-radius: var(--border-radius);
            overflow-x: auto;
            margin: 15px 0;
            font-size: 0.95em;
            border: 1px solid #ddd;
        }}

        code {{
            font-family: 'Courier New', Courier, monospace;
        }}

        .details-section {{
            margin-top: 15px;
            padding-left: 10px;
            border-left: 3px solid #eee;
        }}

        .details-section strong {{
            display: block;
            margin-bottom: 5px;
            color: var(--primary-color);
        }}

        .details-section ul {{
            list-style: none;
            padding-left: 0;
        }}

         .details-section ul li {{
            margin-bottom: 5px;
            font-size: 0.95em;
         }}

        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
            margin-left: 5px;
        }}

        .badge-auth {{ background-color: var(--warning-color); color: #333; }}
        .badge-success {{ background-color: var(--success-color); color: white; }}
        .badge-error {{ background-color: var(--error-color); color: white; }}
        .badge-ratelimit {{ background-color: var(--info-color); color: white; }}

        /* Footer */
        footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ccc;
            color: #555;
            font-size: 0.9em;
        }}

    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Message Broker API Documentation</h1>

        <section id="introduction">
            <h2>👋 Introduction</h2>
            <p>Welcome to the documentation for the Message Broker API V3 (Async/SQLite). This API allows you to manage message queues and publish/consume messages asynchronously.</p>
            <p><strong>Base URL:</strong> <code class="endpoint-path">{API_BASE_URL}</code></p>
            <p><strong>Authentication:</strong> Most endpoints require authentication using JSON Web Tokens (JWT). Obtain a token via the <code>/login</code> endpoint and include it in the <code>Authorization</code> header of subsequent requests as <code>Bearer <your_access_token></code>.</p>
            <p><strong>Content Type:</strong> All request bodies should be JSON (<code>Content-Type: application/json</code>). Responses are also in JSON format.</p>
            <p><strong>Tools:</strong> You can interact with this API using tools like <code>curl</code>, Postman, Insomnia, or programmatically via HTTP clients in your preferred language.</p>
        </section>

        <section id="authentication">
            <h2>🔑 Authentication</h2>

            <div class="card">
                <div class="endpoint-header">
                    <span class="method method-post">POST</span>
                    <span class="endpoint-path">/login</span>
                </div>
                <p>Authenticates a user and returns JWT access and refresh tokens.</p>
                <div class="details-section">
                    <strong>Authentication:</strong> None required.
                </div>
                <div class="details-section">
                    <strong>Rate Limit:</strong> <span class="badge badge-ratelimit">10 per minute</span>
                </div>
                 <div class="details-section">
                    <strong>Request Body:</strong>
                    <pre><code>{{
    "username": "your_username", // e.g., "admin"
    "password": "your_password"  // e.g., "admin"
}}</code></pre>
                </div>
                <div class="details-section">
                    <strong>Success Response (200 OK):</strong>
                    <pre><code>{{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}}</code></pre>
                </div>
                <div class="details-section">
                    <strong>Error Responses:</strong>
                    <ul>
                        <li><span class="badge badge-error">400</span> Bad Request: Invalid payload format.</li>
                        <li><span class="badge badge-error">401</span> Unauthorized: Invalid username or password.</li>
                    </ul>
                </div>
            </div>

            <div class="card">
                <div class="endpoint-header">
                    <span class="method method-post">POST</span>
                    <span class="endpoint-path">/refresh</span>
                </div>
                <p>Generates a new access token using a valid refresh token.</p>
                 <div class="details-section">
                    <strong>Authentication:</strong> <span class="badge badge-auth">JWT Refresh Token Required</span> (Provide refresh token in <code>Authorization: Bearer <refresh_token></code> header).
                </div>
                 <div class="details-section">
                    <strong>Success Response (200 OK):</strong>
                    <pre><code>{{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." // New access token
}}</code></pre>
                </div>
                 <div class="details-section">
                    <strong>Error Responses:</strong>
                    <ul>
                        <li><span class="badge badge-error">401</span> Unauthorized: Invalid or expired refresh token.</li>
                    </ul>
                </div>
            </div>
        </section>

        <section id="queues">
            <h2>📥 Queue Management</h2>

            <div class="card">
                <div class="endpoint-header">
                    <span class="method method-post">POST</span>
                    <span class="endpoint-path">/queues</span>
                </div>
                <p>Creates a new message queue.</p>
                 <div class="details-section">
                    <strong>Authentication:</strong> <span class="badge badge-auth">JWT Access Token Required</span>
                </div>
                <div class="details-section">
                    <strong>Rate Limit:</strong> <span class="badge badge-ratelimit">60 per minute</span>
                </div>
                 <div class="details-section">
                    <strong>Request Body:</strong>
                    <pre><code>{{
    "name": "my-new-queue-name" // String, 1-255 chars, pattern: ^[a-zA-Z0-9_-]+$
}}</code></pre>
                </div>
                <div class="details-section">
                    <strong>Success Response (201 Created):</strong>
                    <pre><code>{{
    "msg": "Queue created",
    "name": "my-new-queue-name",
    "id": 123 // Generated queue ID
}}</code></pre>
                </div>
                 <div class="details-section">
                    <strong>Error Responses:</strong>
                    <ul>
                        <li><span class="badge badge-error">400</span> Bad Request: Invalid payload (e.g., name format).</li>
                        <li><span class="badge badge-error">401</span> Unauthorized: Missing/Invalid JWT token.</li>
                        <li><span class="badge badge-error">409</span> Conflict: Queue name already exists.</li>
                        <li><span class="badge badge-error">500</span> Internal Server Error: Database error.</li>
                    </ul>
                </div>
            </div>

            <div class="card">
                <div class="endpoint-header">
                    <span class="method method-get">GET</span>
                    <span class="endpoint-path">/queues</span>
                </div>
                <p>Lists all existing message queues.</p>
                 <div class="details-section">
                    <strong>Authentication:</strong> <span class="badge badge-auth">JWT Access Token Required</span>
                </div>
                <div class="details-section">
                    <strong>Rate Limit:</strong> <span class="badge badge-ratelimit">100 per minute</span>
                </div>
                 <div class="details-section">
                    <strong>Success Response (200 OK):</strong>
                    <pre><code>[
    {{
        "id": 1,
        "name": "email-notifications",
        "created_at": "2025-04-03T10:00:00Z"
    }},
    {{
        "id": 2,
        "name": "image-processing",
        "created_at": "2025-04-03T11:30:00Z"
    }}
    // ... more queues
]</code></pre>
                </div>
                 <div class="details-section">
                    <strong>Error Responses:</strong>
                    <ul>
                         <li><span class="badge badge-error">401</span> Unauthorized: Missing/Invalid JWT token.</li>
                         <li><span class="badge badge-error">500</span> Internal Server Error: Database error.</li>
                    </ul>
                </div>
            </div>

            <div class="card">
                <div class="endpoint-header">
                    <span class="method method-get">GET</span>
                    <span class="endpoint-path">/queues/{'{queue_name}'}</span>
                </div>
                <p>Retrieves details for a specific queue, including the count of pending messages.</p>
                 <div class="details-section">
                    <strong>Authentication:</strong> <span class="badge badge-auth">JWT Access Token Required</span>
                </div>
                <div class="details-section">
                    <strong>Rate Limit:</strong> <span class="badge badge-ratelimit">100 per minute</span>
                </div>
                <div class="details-section">
                    <strong>URL Parameters:</strong>
                    <ul>
                        <li><code>queue_name</code> (string): The name of the queue to retrieve.</li>
                    </ul>
                </div>
                 <div class="details-section">
                    <strong>Success Response (200 OK):</strong>
                    <pre><code>{{
    "id": 1,
    "name": "email-notifications",
    "created_at": "2025-04-03T10:00:00Z",
    "pending_messages": 42
}}</code></pre>
                </div>
                 <div class="details-section">
                    <strong>Error Responses:</strong>
                    <ul>
                        <li><span class="badge badge-error">401</span> Unauthorized: Missing/Invalid JWT token.</li>
                        <li><span class="badge badge-error">404</span> Not Found: The specified queue name does not exist.</li>
                        <li><span class="badge badge-error">500</span> Internal Server Error: Database error.</li>
                    </ul>
                </div>
            </div>

            <div class="card">
                <div class="endpoint-header">
                    <span class="method method-delete">DELETE</span>
                    <span class="endpoint-path">/queues/{'{queue_name}'}</span>
                </div>
                <p>Deletes a specific queue and all messages within it.</p>
                 <div class="details-section">
                    <strong>Authentication:</strong> <span class="badge badge-auth">JWT Access Token Required</span>
                </div>
                <div class="details-section">
                    <strong>Rate Limit:</strong> <span class="badge badge-ratelimit">30 per minute</span>
                </div>
                 <div class="details-section">
                    <strong>URL Parameters:</strong>
                    <ul>
                        <li><code>queue_name</code> (string): The name of the queue to delete.</li>
                    </ul>
                </div>
                 <div class="details-section">
                    <strong>Success Response (200 OK):</strong>
                    <pre><code>{{
    "msg": "Queue 'queue-to-delete' deleted"
}}</code></pre>
                </div>
                 <div class="details-section">
                    <strong>Error Responses:</strong>
                    <ul>
                        <li><span class="badge badge-error">401</span> Unauthorized: Missing/Invalid JWT token.</li>
                        <li><span class="badge badge-error">404</span> Not Found: The specified queue name does not exist.</li>
                        <li><span class="badge badge-error">500</span> Internal Server Error: Database error.</li>
                    </ul>
                </div>
            </div>
        </section>

        <section id="messages">
            <h2>✉️ Message Handling</h2>

             <div class="card">
                <div class="endpoint-header">
                    <span class="method method-post">POST</span>
                    <span class="endpoint-path">/queues/{'{queue_name}'}/messages</span>
                </div>
                <p>Publishes a new message to the specified queue.</p>
                 <div class="details-section">
                    <strong>Authentication:</strong> <span class="badge badge-auth">JWT Access Token Required</span>
                </div>
                <div class="details-section">
                    <strong>Rate Limit:</strong> <span class="badge badge-ratelimit">500 per minute</span>
                </div>
                <div class="details-section">
                    <strong>URL Parameters:</strong>
                    <ul>
                        <li><code>queue_name</code> (string): The name of the target queue.</li>
                    </ul>
                </div>
                 <div class="details-section">
                    <strong>Request Body:</strong>
                    <pre><code>{{
    "content": {{ // Can be JSON object, string, or array
        "user_id": 123,
        "task": "send_welcome_email",
        "template": "welcome_v1"
    }}
}}</code></pre>
                    <pre><code>{{
    "content": "Simple string message"
}}</code></pre>
                    <pre><code>{{
    "content": ["item1", "item2", 123]
}}</code></pre>
                </div>
                <div class="details-section">
                    <strong>Success Response (201 Created):</strong>
                    <pre><code>{{
    "msg": "Message published",
    "message_id": 5678 // Generated message ID
}}</code></pre>
                </div>
                 <div class="details-section">
                    <strong>Error Responses:</strong>
                    <ul>
                        <li><span class="badge badge-error">400</span> Bad Request: Invalid payload format.</li>
                        <li><span class="badge badge-error">401</span> Unauthorized: Missing/Invalid JWT token.</li>
                        <li><span class="badge badge-error">404</span> Not Found: The specified queue name does not exist.</li>
                        <li><span class="badge badge-error">500</span> Internal Server Error: Database error.</li>
                    </ul>
                </div>
                 <div class="details-section">
                     <strong>Note:</strong> On success, an SSE event is published to the queue's channel.
                 </div>
            </div>

             <div class="card">
                <div class="endpoint-header">
                    <span class="method method-get">GET</span>
                    <span class="endpoint-path">/queues/{'{queue_name}'}/messages</span>
                </div>
                <p>Consumes the oldest pending message from the specified queue. Marks the message as 'processing'.</p>
                 <div class="details-section">
                    <strong>Authentication:</strong> <span class="badge badge-auth">JWT Access Token Required</span>
                </div>
                <div class="details-section">
                    <strong>Rate Limit:</strong> <span class="badge badge-ratelimit">200 per minute</span>
                </div>
                <div class="details-section">
                    <strong>URL Parameters:</strong>
                    <ul>
                        <li><code>queue_name</code> (string): The name of the queue to consume from.</li>
                    </ul>
                </div>
                 <div class="details-section">
                    <strong>Success Response (200 OK):</strong>
                    <pre><code>{{
    "message_id": 5678,
    "queue": "email-notifications",
    "content": {{ // The original message content
        "user_id": 123,
        "task": "send_welcome_email",
        "template": "welcome_v1"
    }},
    "status": "processing",
    "retrieved_at": "2025-04-03T12:00:00Z"
}}</code></pre>
                </div>
                 <div class="details-section">
                    <strong>Success Response (204 No Content):</strong>
                    <ul>
                         <li>Returned when there are no pending messages in the queue. The response body is empty.</li>
                    </ul>
                 </div>
                 <div class="details-section">
                    <strong>Error Responses:</strong>
                    <ul>
                        <li><span class="badge badge-error">401</span> Unauthorized: Missing/Invalid JWT token.</li>
                        <li><span class="badge badge-error">404</span> Not Found: The specified queue name does not exist.</li>
                        <li><span class="badge badge-error">500</span> Internal Server Error: Database error during consumption.</li>
                    </ul>
                 </div>
                  <div class="details-section">
                     <strong>Important:</strong> After successfully processing the message content received here, you <strong>must</strong> call the ACK (<code>/messages/{'{message_id}'}/ack</code>) or NACK (<code>/messages/{'{message_id}'}/nack</code>) endpoint. Failure to do so will leave the message in the 'processing' state indefinitely.
                 </div>
            </div>

             <div class="card">
                <div class="endpoint-header">
                    <span class="method method-post">POST</span>
                    <span class="endpoint-path">/messages/{'{message_id}'}/ack</span>
                </div>
                <p>✅ Acknowledges successful processing of a message. Marks the message as 'processed'.</p>
                 <div class="details-section">
                    <strong>Authentication:</strong> <span class="badge badge-auth">JWT Access Token Required</span>
                </div>
                <div class="details-section">
                    <strong>Rate Limit:</strong> <span class="badge badge-ratelimit">200 per minute</span>
                </div>
                 <div class="details-section">
                    <strong>URL Parameters:</strong>
                    <ul>
                        <li><code>message_id</code> (integer): The ID of the message to acknowledge.</li>
                    </ul>
                </div>
                <div class="details-section">
                    <strong>Request Body:</strong> None.
                </div>
                 <div class="details-section">
                    <strong>Success Response (200 OK):</strong>
                    <pre><code>{{
    "msg": "Message 5678 acknowledged"
}}</code></pre>
                </div>
                 <div class="details-section">
                    <strong>Error Responses:</strong>
                    <ul>
                        <li><span class="badge badge-error">401</span> Unauthorized: Missing/Invalid JWT token.</li>
                        <li><span class="badge badge-error">403</span> Forbidden: You are not the consumer who retrieved this message.</li>
                        <li><span class="badge badge-error">404</span> Not Found: The specified message ID does not exist.</li>
                        <li><span class="badge badge-error">409</span> Conflict: The message is not in the 'processing' state.</li>
                        <li><span class="badge badge-error">500</span> Internal Server Error: Database error.</li>
                    </ul>
                </div>
                 <div class="details-section">
                     <strong>Note:</strong> On success, an SSE event is published to the message's queue channel.
                 </div>
            </div>

             <div class="card">
                <div class="endpoint-header">
                    <span class="method method-post">POST</span>
                    <span class="endpoint-path">/messages/{'{message_id}'}/nack</span>
                </div>
                <p>❌ Negatively acknowledges a message, indicating processing failed. Marks the message as 'failed'. (No automatic retry or DLQ implemented in this version).</p>
                 <div class="details-section">
                    <strong>Authentication:</strong> <span class="badge badge-auth">JWT Access Token Required</span>
                </div>
                <div class="details-section">
                    <strong>Rate Limit:</strong> <span class="badge badge-ratelimit">200 per minute</span>
                </div>
                 <div class="details-section">
                    <strong>URL Parameters:</strong>
                    <ul>
                        <li><code>message_id</code> (integer): The ID of the message to NACK.</li>
                    </ul>
                </div>
                 <div class="details-section">
                    <strong>Request Body:</strong> None. (Optionally could accept a 'reason').
                </div>
                 <div class="details-section">
                    <strong>Success Response (200 OK):</strong>
                    <pre><code>{{
    "msg": "Message 5678 marked as failed (NACK)"
}}</code></pre>
                </div>
                 <div class="details-section">
                    <strong>Error Responses:</strong>
                    <ul>
                        <li><span class="badge badge-error">401</span> Unauthorized: Missing/Invalid JWT token.</li>
                        <li><span class="badge badge-error">403</span> Forbidden: You are not the consumer who retrieved this message.</li>
                        <li><span class="badge badge-error">404</span> Not Found: The specified message ID does not exist.</li>
                        <li><span class="badge badge-error">409</span> Conflict: The message is not in the 'processing' state.</li>
                        <li><span class="badge badge-error">500</span> Internal Server Error: Database error.</li>
                    </ul>
                </div>
                 <div class="details-section">
                     <strong>Note:</strong> On success, an SSE event is published to the message's queue channel.
                 </div>
            </div>
        </section>

        <section id="stats">
            <h2>📊 Statistics</h2>
            <div class="card">
                <div class="endpoint-header">
                    <span class="method method-get">GET</span>
                    <span class="endpoint-path">/stats</span>
                </div>
                <p>Retrieves detailed statistics about the broker and the system it's running on.</p>
                <div class="details-section">
                    <strong>Authentication:</strong> <span class="badge badge-auth">JWT Access Token Required</span>
                </div>
                <div class="details-section">
                    <strong>Rate Limit:</strong> <span class="badge badge-ratelimit">30 per minute</span>
                </div>
                <div class="details-section">
                    <strong>Success Response (200 OK):</strong>
                    <pre><code>{{
    "start_time": "2025-04-03T09:00:00Z",
    "requests_total": 1500,
    "requests_by_route": {{
        "/queues": {{ "GET": 500, "POST": 100 }},
        "/queues/<string:queue_name>/messages": {{ "GET": 400, "POST": 450 }},
        // ... other routes
    }},
    "requests_by_status": {{
        "200": 1200, "201": 100, "204": 50, "404": 100, "401": 50
    }},
    "queues_total": 5,
    "messages_total": 10000,
    "messages_pending": 2000,
    "messages_processing": 50,
    "messages_processed": 7800,
    "messages_failed": 150,
    "last_error": null, // or "DB Stats Update Failed: 2025-04-03T13:00:00Z"
    "system": {{
        "python_version": "3.10.x",
        "platform": "Linux", // or "Windows", "Darwin"
        "platform_release": "5.15.0-...",
        "architecture": "x86_64",
        "cpu_percent": 15.5,
        "memory_total_gb": 15.6,
        "memory_available_gb": 8.2,
        "memory_used_gb": 7.4,
        "memory_percent": 47.4,
        "disk_usage": {{
            "/": {{ "total_gb": 99.5, "used_gb": 40.2, "free_gb": 59.3, "percent": 40.4 }}
            // ... other mounted disks
        }},
        "process_memory_mb": 120.5,
        "process_cpu_percent": 2.1
    }},
    "broker_specific": {{
        "db_engine": "sqlite (aiosqlite)",
        "auth_method": "jwt (access+refresh)",
        "notification": "sse (redis)",
        "rate_limit": "redis"
    }},
    "uptime_seconds": 36000.5,
    "uptime_human": "10:00:00"
}}</code></pre>
                </div>
                 <div class="details-section">
                    <strong>Error Responses:</strong>
                    <ul>
                        <li><span class="badge badge-error">401</span> Unauthorized: Missing/Invalid JWT token.</li>
                        <li><span class="badge badge-error">500</span> Internal Server Error: If stats collection fails badly.</li>
                    </ul>
                </div>
            </div>
        </section>

         <section id="logs">
            <h2>📄 Log Viewing</h2>
             <p>These endpoints allow viewing the JSON log files generated by the broker.</p>

            <div class="card">
                <div class="endpoint-header">
                    <span class="method method-get">GET</span>
                    <span class="endpoint-path">/logs</span>
                </div>
                <p>Lists the available JSON log files, sorted newest first.</p>
                <div class="details-section">
                    <strong>Authentication:</strong> <span class="badge badge-auth">JWT Access Token Required</span>
                </div>
                <div class="details-section">
                    <strong>Rate Limit:</strong> <span class="badge badge-ratelimit">10 per minute</span>
                </div>
                <div class="details-section">
                    <strong>Success Response (200 OK):</strong>
                    <pre><code>{{
    "log_files": [
        "broker_log_20250403_140000_abcdef12.json",
        "broker_log_20250403_130000_fedcba98.json"
        // ... other log files
    ]
}}</code></pre>
                </div>
                 <div class="details-section">
                    <strong>Error Responses:</strong>
                    <ul>
                        <li><span class="badge badge-error">401</span> Unauthorized: Missing/Invalid JWT token.</li>
                        <li><span class="badge badge-error">500</span> Internal Server Error: Error reading log directory.</li>
                    </ul>
                </div>
            </div>

             <div class="card">
                <div class="endpoint-header">
                    <span class="method method-get">GET</span>
                    <span class="endpoint-path">/logs/{'{filename}'}</span>
                </div>
                <p>Retrieves the content of a specific log file.</p>
                <div class="details-section">
                    <strong>Authentication:</strong> <span class="badge badge-auth">JWT Access Token Required</span>
                </div>
                <div class="details-section">
                    <strong>Rate Limit:</strong> <span class="badge badge-ratelimit">60 per minute</span>
                </div>
                 <div class="details-section">
                    <strong>URL Parameters:</strong>
                    <ul>
                        <li><code>filename</code> (string): The exact name of the JSON log file to retrieve (e.g., <code>broker_log_20250403_140000_abcdef12.json</code>).</li>
                    </ul>
                </div>
                 <div class="details-section">
                    <strong>Query Parameters (Optional):</strong>
                    <ul>
                        <li><code>start</code> (integer): Line number to start reading from (1-based index).</li>
                        <li><code>end</code> (integer): Line number to stop reading at (inclusive).</li>
                        <li><code>tail</code> (integer): Retrieve only the last N lines. (Takes precedence over start/end if provided).</li>
                    </ul>
                 </div>
                 <div class="details-section">
                    <strong>Success Response (200 OK):</strong> Returns a JSON array, where each element is a parsed JSON log entry from a line in the file.
                    <pre><code>[
    {{ // Log Entry 1
        "timestamp": "2025-04-03T14:00:01.123Z",
        "level": "INFO",
        "name": "MessageBrokerV3",
        "pid": 12345,
        "thread": "MainThread",
        "message": "🚀 Initializing Flask Application...",
        "icon_type": "INFO"
    }},
    {{ // Log Entry 2
        "timestamp": "2025-04-03T14:00:05.456Z",
        "level": "ERROR",
        "name": "MessageBrokerV3",
        "pid": 12345,
        "thread": "Thread-2",
        "message": "Database error consuming message from 'image-processing' (SQLite): database is locked",
        "icon_type": "DB",
        "exception": "Traceback (most recent call last):...",
        "traceback": [ "..." ] // Full traceback array if exception occurred
    }}
    // ... more log entries
]</code></pre>
                 <p>If a line in the log file is not valid JSON, it will be represented as:</p>
                 <pre><code>{{
    "_error": "Invalid JSON",
    "_line": 15, // The line number where the error occurred
    "_raw": "This was not json {{ "maybe" }}
}}
</code></pre>
                </div>
                 <div class="details-section">
                    <strong>Error Responses:</strong>
                    <ul>
                        <li><span class="badge badge-error">400</span> Bad Request: Invalid filename.</li>
                        <li><span class="badge badge-error">401</span> Unauthorized: Missing/Invalid JWT token.</li>
                        <li><span class="badge badge-error">404</span> Not Found: The specified log file does not exist.</li>
                        <li><span class="badge badge-error">500</span> Internal Server Error: Error reading the log file.</li>
                    </ul>
                </div>
            </div>
        </section>

         <section id="graphql">
            <h2>🍇 GraphQL API</h2>

            <div class="card">
                <div class="endpoint-header">
                    <span class="method method-post">POST</span> / <span class="method method-get">GET</span>
                    <span class="endpoint-path">/graphql</span>
                </div>
                <p>Provides a GraphQL endpoint for querying queues and messages.</p>
                 <div class="details-section">
                    <strong>Authentication:</strong> <span class="badge badge-auth">JWT Access Token Required</span>
                </div>
                <div class="details-section">
                    <strong>Interface:</strong> Supports GET requests for introspection and POST requests for queries/mutations (though only queries are defined here). Accessing this endpoint in a browser typically shows the GraphiQL interface for interactive exploration.
                </div>
                 <div class="details-section">
                     <strong>Available Queries:</strong>
                     <ul>
                        <li><code>allQueues</code>: Retrieves a list of all queues (supports pagination/sorting via Relay connections).</li>
                        <li><code>queueByName(name: String!)</code>: Retrieves a single queue by its exact name.</li>
                        <li><code>messagesInQueue(queueName: String!, status: String, limit: Int)</code>: Retrieves messages for a specific queue, optionally filtering by status ('pending', 'processing', 'processed', 'failed') and limiting the result count (default 100).</li>
                     </ul>
                 </div>
                <div class="details-section">
                    <strong>Example GraphQL Query (POST Request Body):</strong>
                    <pre><code>{{
    "query": \"\"\"
        query {{
          q1: queueByName(name: "email-notifications") {{
            id
            name
            createdAt
          }}
          pendingMessages: messagesInQueue(queueName: "image-processing", status: "pending", limit: 5) {{
            edges {{
              node {{
                id
                status
                createdAt
                content
              }}
            }}
          }}
        }}
    \"\"\"
}}</code></pre>
                </div>
                <div class="details-section">
                    <strong>Success Response (200 OK):</strong> The structure mirrors the GraphQL query.
                    <pre><code>{{
    "data": {{
        "q1": {{
            "id": "UXVldWVPYmplY3Q6MQ==", // Base64 encoded Relay ID
            "name": "email-notifications",
            "createdAt": "2025-04-03T10:00:00+00:00"
        }},
        "pendingMessages": {{
             "edges": [
                {{ "node": {{ "id": "TWVzc2FnZU9iamVjdDo1...", "status": "pending", ... }} }},
                {{ "node": {{ "id": "TWVzc2FnZU9iamVjdDo2...", "status": "pending", ... }} }}
             ]
        }}
    }}
}}</code></pre>
                </div>
                 <div class="details-section">
                    <strong>Error Responses:</strong> GraphQL has its own error reporting format within the JSON response, typically under an "errors" key. HTTP status is usually 200 even if the query fails, unless there's an authentication issue (401) or server error (500).
                    <ul>
                        <li><span class="badge badge-error">401</span> Unauthorized: Missing/Invalid JWT token.</li>
                    </ul>
                 </div>
            </div>
        </section>

        <section id="sse">
            <h2>📡 Server-Sent Events (SSE)</h2>

            <div class="card">
                 <div class="endpoint-header">
                    <span class="method method-get">GET</span>
                    <span class="endpoint-path">/stream</span>
                 </div>
                 <p>Establishes a Server-Sent Events connection to receive real-time notifications about message events.</p>
                  <div class="details-section">
                    <strong>Authentication:</strong> None required for the stream connection itself (consider adding JWT query param auth if needed for specific use cases).
                  </div>
                  <div class="details-section">
                    <strong>How it Works:</strong>
                    <ul>
                        <li>Clients connect to this endpoint using the standard <code>EventSource</code> API in JavaScript (or equivalent in other languages).</li>
                        <li>The server keeps this connection open and pushes events as they happen.</li>
                        <li>Events are published by the server when:
                            <ul>
                                <li>A new message is published (event type: <code>message</code>, channel: <code>queue_name</code>).</li>
                                <li>A message is acknowledged (event type: <code>message</code>, channel: <code>queue_name</code>).</li>
                                <li>A message is NACKed (event type: <code>message</code>, channel: <code>queue_name</code>).</li>
                            </ul>
                        </li>
                        <li>The <code>channel</code> parameter in the SSE URL (e.g., <code>/stream?channel=my-queue</code>) is used by the <em>client</em> library (like the official `flask-sse` JS client) to filter messages client-side if needed, but the Python backend currently publishes events with the queue name embedded in the data and tagged with the queue name as the channel type. You might need a specific client library or custom JS to listen only to specific queue channels effectively based on the pushed data or type.</li>
                    </ul>
                  </div>
                  <div class="details-section">
                      <strong>Example JavaScript Client:</strong>
                      <pre><code>// Assuming you want events for the 'email-notifications' queue
const eventSource = new EventSource("{API_BASE_URL}/stream"); // Connect to the main stream

eventSource.onmessage = function(event) {{
    console.log("Raw message received:", event.data);
    try {{
        const data = JSON.parse(event.data);

        // Check if the message is for the queue we care about
        if (data.queue === "email-notifications") {{
            console.log(`Event for email-notifications:`, data);
            // Handle the event (e.g., update UI)
            if (data.event === "new_message") {{
                console.log(`New message ${'{data.message_id}'} published.`);
            }} else if (data.event === "message_acked") {{
                 console.log(`Message ${'{data.message_id}'} acknowledged.`);
            }} else if (data.event === "message_nacked") {{
                 console.log(`Message ${'{data.message_id}'} failed.`);
            }}
        }}
    }} catch (e) {{
        console.error("Failed to parse SSE data:", e);
    }}
}};

eventSource.onerror = function(err) {{
    console.error("EventSource failed:", err);
    // Handle errors, maybe attempt reconnection
}};

// To close the connection:
// eventSource.close();
</code></pre>
                  </div>
                  <div class="details-section">
                    <strong>Event Data Format:</strong> The data field of each SSE message is a JSON string like:
                    <pre><code>{{
    "queue": "queue_name",      // Name of the queue the event pertains to
    "message_id": 12345,        // ID of the relevant message
    "event": "new_message"      // Type of event ("new_message", "message_acked", "message_nacked")
}}</code></pre>
                  </div>
            </div>
        </section>

        <footer>
            Message Broker API V3 Docs - Served by Flask
        </footer>
    </div>
</body>
</html>
"""

@app.route('/')
def serve_documentation():
    """Serves the main HTML documentation page."""
    # Use Response object for explicit content type and status
    return Response(HTML_CONTENT, mimetype='text/html', status=200)

if __name__ == '__main__':
    print(f" * Starting documentation server on http://localhost:{DOC_SERVER_PORT}")
    # Use waitress or gunicorn in production instead of Flask's development server
    # For simplicity here, we use the built-in server.
    # Use host='0.0.0.0' to make it accessible from other devices on the network
    app.run(host='0.0.0.0', port=DOC_SERVER_PORT, debug=False)