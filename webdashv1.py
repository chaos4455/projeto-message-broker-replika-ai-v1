# dashboard_server.py
import os
import time
import threading
import logging
from collections import deque
from threading import Lock
from datetime import datetime, timezone
import json # Import json for potential decoding errors

import requests # Para fazer requisições à API principal
import schedule # Para agendar a coleta de dados
from flask import Flask, Response, jsonify, render_template_string
from flask_cors import CORS

# --- Configuração ---
DASHBOARD_PORT = 8333
API_BASE_URL = os.environ.get("API_BASE_URL", "https://127.0.0.1:8777") # Use HTTPS for the API
API_STATS_URL = f"{API_BASE_URL}/stats"
API_LOGIN_URL = f"{API_BASE_URL}/login"

# Credentials for the dashboard to access the main API
# !!! Use environment variables in production !!!
API_USERNAME = os.environ.get("API_USER", "admin")
API_PASSWORD = os.environ.get("API_PASS", "admin")

FETCH_INTERVAL_SECONDS = 5 # Intervalo de coleta de dados
MAX_CHART_HISTORY = 60 # Pontos no histórico para gráficos de linha

# --- Configuração de Logging ---
# Use basicConfig or integrate with Flask's logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('webdashv1') # Use a specific name for the dashboard logger

# --- Estado Global e Controle ---
app_state = {
    "latest_stats": {},
    "last_error": None,
    "last_successful_fetch": None,
    "api_token": None, # Store only the access token
    "refresh_token": None, # Store refresh token if API supports refresh logic
    "login_needed": True,
    "is_fetching": False, # Flag to prevent concurrent fetches
    # Histórico para gráficos
    "time_labels": deque(maxlen=MAX_CHART_HISTORY),
    "request_history": deque(maxlen=MAX_CHART_HISTORY), # Deltas por intervalo
    "message_status_history": {
        "pending": deque(maxlen=MAX_CHART_HISTORY),
        "processing": deque(maxlen=MAX_CHART_HISTORY),
        "failed": deque(maxlen=MAX_CHART_HISTORY),
        "processed": deque(maxlen=MAX_CHART_HISTORY),
    },
    "performance_history": {
        "cpu": deque(maxlen=MAX_CHART_HISTORY),
        "memory": deque(maxlen=MAX_CHART_HISTORY),
    },
    "previous_total_requests": 0 # Para calcular delta
}
data_lock = Lock() # Para proteger o acesso concorrente ao app_state

# --- Funções de Coleta e Processamento ---

def login_to_api():
    """Tenta fazer login na API principal e armazena os tokens."""
    global app_state
    logger.info(f"Attempting login to API at {API_LOGIN_URL}...")
    try:
        # Use data payload for standard OAuth2 Password Flow
        login_data = {'username': API_USERNAME, 'password': API_PASSWORD}

        # IMPORTANT: Disable SSL verification ONLY for local dev with self-signed certs
        # In production, use verify=True or path to your CA bundle
        response = requests.post(API_LOGIN_URL, data=login_data, verify=False, timeout=10)

        response.raise_for_status() # Lança exceção para erros HTTP 4xx/5xx

        token_data = response.json()
        if "access_token" in token_data and "refresh_token" in token_data:
            with data_lock:
                app_state["api_token"] = token_data["access_token"]
                app_state["refresh_token"] = token_data["refresh_token"] # Store if needed later
                app_state["login_needed"] = False
                app_state["last_error"] = None # Limpa erro de login anterior
            logger.info("API login successful.")
            return True
        else:
            logger.error("API login response missing 'access_token' or 'refresh_token'.")
            with data_lock:
                app_state["last_error"] = "Login response missing tokens"
                app_state["api_token"] = None
                app_state["refresh_token"] = None
                app_state["login_needed"] = True
            return False

    except requests.exceptions.RequestException as e:
        status_code = getattr(e.response, 'status_code', 'N/A')
        error_detail = f"Status: {status_code}"
        try:
             # Try to get more details from response body
             if e.response is not None:
                 # Check content type before assuming JSON
                 content_type = e.response.headers.get('Content-Type', '')
                 if 'application/json' in content_type:
                    error_json = e.response.json()
                    error_detail += f" - Detail: {error_json.get('detail', error_json)}"
                 else:
                    error_detail += f" - Response: {e.response.text[:200]}" # Log snippet of non-JSON
        except Exception: pass # Ignore if can't read response body or decode JSON
        logger.error(f"API login failed ({error_detail}): {e}")
        with data_lock:
            app_state["last_error"] = f"Login request failed: {e}" # Store generic error
            app_state["api_token"] = None
            app_state["refresh_token"] = None
            app_state["login_needed"] = True
        return False
    except json.JSONDecodeError as e:
        # Handle cases where the response is not valid JSON
        response_text = getattr(e, 'doc', '') or getattr(e.response, 'text', 'N/A')
        logger.error(f"API login failed: Could not decode JSON response. Response text: {response_text[:500]}")
        with data_lock:
            app_state["last_error"] = "Login response was not valid JSON"
            app_state["api_token"] = None
            app_state["refresh_token"] = None
            app_state["login_needed"] = True
        return False
    except Exception as e:
        logger.error(f"Unexpected error during API login: {e}", exc_info=True) # Log traceback for unexpected errors
        with data_lock:
            app_state["last_error"] = f"Unexpected login error: {e}"
            app_state["api_token"] = None
            app_state["refresh_token"] = None
            app_state["login_needed"] = True
        return False


def fetch_api_data():
    """Busca dados de /stats da API principal, handling authentication."""
    global app_state

    # Prevent concurrent fetches
    with data_lock:
        if app_state.get("is_fetching", False):
            logger.debug("Fetch cycle skipped, already fetching.")
            return
        app_state["is_fetching"] = True
        # Get needed state values under lock
        token = app_state["api_token"]
        login_needed = app_state["login_needed"]

    # Release lock before network I/O
    logger.debug("Starting data fetch cycle...")

    try: # Outer try for managing the 'is_fetching' flag
        # --- Handle Authentication ---
        if login_needed or not token:
            logger.warning("Login required or token missing, attempting login...")
            if not login_to_api():
                logger.error("Fetch cycle aborted due to login failure.")
                # Update state with login error if login_to_api didn't already
                with data_lock:
                     if app_state["last_error"] is None:
                         app_state["last_error"] = "Login required but failed"
                return # Exit fetch cycle

            # Re-fetch the token after successful login (under lock)
            with data_lock:
                token = app_state["api_token"]
                # If token is *still* missing after a successful login_to_api call, something is wrong
                if not token:
                     logger.error("CRITICAL: Token still missing after supposedly successful login. Aborting fetch cycle.")
                     app_state["last_error"] = "Internal dashboard error: Token lost after login."
                     return

        # --- Fetch Stats Data ---
        logger.debug(f"Fetching stats from {API_STATS_URL}...")
        headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/json'}

        try:
            # Again, disable SSL verification ONLY for local dev
            response = requests.get(API_STATS_URL, headers=headers, verify=False, timeout=10)

            # Check for auth errors first
            if response.status_code == 401 or response.status_code == 403:
                logger.warning(f"API returned {response.status_code} (Unauthorized/Forbidden) fetching stats. Token likely expired. Forcing re-login.")
                with data_lock:
                    app_state["api_token"] = None
                    # Decide whether to clear refresh token too
                    # app_state["refresh_token"] = None
                    app_state["login_needed"] = True
                    app_state["last_error"] = f"API Auth error ({response.status_code}). Re-login needed."
                # No need to call login_to_api() here, it will happen at the start of the next cycle
                return # Abort this cycle

            # Check for other HTTP errors
            response.raise_for_status()

            # ---- Process Successful Response ----
            try:
                stats = response.json()
                now = datetime.now(timezone.utc)
                logger.debug("Stats received successfully from API.")

                # Process and update the state under lock
                with data_lock:
                    app_state["latest_stats"] = stats # Store the raw stats object
                    app_state["last_successful_fetch"] = now.isoformat()
                    app_state["last_error"] = None # Clear errors on success

                    # --- Update history deques ---
                    current_time_label = now.strftime("%H:%M:%S")
                    app_state["time_labels"].append(current_time_label)

                    # Calculate request delta safely
                    current_total_requests = stats.get("requests_total")
                    request_delta = 0 # Default if calculation fails
                    if isinstance(current_total_requests, int):
                        prev_total = app_state["previous_total_requests"]
                        # Ensure previous total is also valid before subtracting
                        request_delta = max(0, current_total_requests - (prev_total if isinstance(prev_total, int) else 0))
                        app_state["previous_total_requests"] = current_total_requests # Update for next cycle
                    else:
                        logger.warning(f"`requests_total` missing or not integer in stats response: {current_total_requests}. Delta calculation skipped.")

                    app_state["request_history"].append(request_delta)

                    # Update message history (use .get with default 0)
                    app_state["message_status_history"]["pending"].append(stats.get("messages_pending", 0))
                    app_state["message_status_history"]["processing"].append(stats.get("messages_processing", 0))
                    app_state["message_status_history"]["failed"].append(stats.get("messages_failed", 0))
                    app_state["message_status_history"]["processed"].append(stats.get("messages_processed", 0))

                    # Update performance history (handle potential missing nested keys gracefully)
                    system_stats = stats.get("system", {}) # Default to empty dict if 'system' is missing
                    cpu = system_stats.get("process_cpu_percent")
                    mem = system_stats.get("process_memory_mb")
                    # Ensure values are numeric before appending, default to 0
                    app_state["performance_history"]["cpu"].append(cpu if isinstance(cpu, (int, float)) else 0)
                    app_state["performance_history"]["memory"].append(mem if isinstance(mem, (int, float)) else 0)

                logger.debug("Dashboard state updated with new stats and history.")

            except json.JSONDecodeError as e:
                 logger.error(f"Failed to decode JSON response from API /stats: {e}. Response text: {response.text[:500]}")
                 with data_lock:
                      app_state["last_error"] = "API /stats response is not valid JSON"
            except Exception as processing_e: # Catch errors during state update/processing
                logger.error(f"Error processing received stats: {processing_e}", exc_info=True)
                with data_lock:
                    app_state["last_error"] = f"Error processing stats: {processing_e}"


        # --- Handle Request Errors ---
        except requests.exceptions.Timeout:
            logger.error("API /stats request timed out.")
            with data_lock: app_state["last_error"] = "API Timeout fetching stats"
        except requests.exceptions.ConnectionError as e:
            logger.error(f"API /stats connection error: {e}")
            with data_lock: app_state["last_error"] = f"API Connection Error: {e}"
        except requests.exceptions.RequestException as e:
             # This catches other HTTP errors (like 500, 404 etc.) not handled above
            status_code = getattr(e.response, 'status_code', 'N/A')
            logger.error(f"API /stats request failed (Status: {status_code}): {e}")
            error_detail = f"API Request Failed: {e}"
            try: # Attempt to get response details
                if e.response is not None:
                    error_detail += f" - Response: {e.response.text[:200]}"
            except Exception: pass
            with data_lock:
                 # Avoid overwriting a more specific auth error logged earlier in the cycle
                 if app_state.get("last_error") is None or "Auth error" not in app_state["last_error"]:
                     app_state["last_error"] = error_detail

    except Exception as outer_e:
         # Catch errors in the logic before the actual request (e.g., token fetching issues missed)
        logger.error(f"Unexpected error during data fetch setup: {outer_e}", exc_info=True)
        with data_lock:
            app_state["last_error"] = f"Unexpected Fetch Error: {outer_e}"

    finally:
        # Ensure the fetching flag is reset even if errors occur
        with data_lock:
            app_state["is_fetching"] = False


def run_scheduler():
    """Executa o loop do agendador em uma thread separada."""
    logger.info("Scheduler thread started.")
    # Perform an initial fetch immediately before starting the scheduled loop
    # This helps populate the dashboard faster on startup
    try:
        fetch_api_data()
    except Exception as e:
         logger.error(f"Error during initial data fetch: {e}", exc_info=True)

    # Schedule the regular fetching task
    schedule.every(FETCH_INTERVAL_SECONDS).seconds.do(fetch_api_data)

    # Keep the scheduler running
    while True:
        try:
            schedule.run_pending()
        except Exception as e:
             # Catch potential errors within the scheduler loop itself or the scheduled job
             logger.error(f"Error in scheduler loop: {e}", exc_info=True)
             # Avoid busy-waiting in case of continuous errors
        time.sleep(1) # Check schedule every second

# --- Flask App ---
app = Flask(__name__)
# Configure Flask logger to use our handler setup
app.logger.handlers = logger.handlers
app.logger.setLevel(logger.level)
CORS(app) # Enable CORS for all routes by default

# --- HTML Content (CRITICAL FIX: Added {% raw %} blocks) ---
HTML_CONTENT = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Metrics Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    {# Add a simple Favicon using SVG inline #}
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><path d=%22M8.3 25L41.7 8.3L75 25L41.7 41.7L8.3 25Z%22 stroke=%22%2300bcd4%22 stroke-width=%2210%22 fill=%22none%22/><path d=%22M8.3 75L41.7 58.3L75 75L41.7 91.7L8.3 75Z%22 stroke=%22%2300bcd4%22 stroke-width=%2210%22 fill=%22none%22/><path d=%22M8.3 50H75%22 stroke=%22%2300bcd4%22 stroke-width=%2210%22 fill=%22none%22/></svg>">

    {# ***** START RAW BLOCK FOR CSS ***** #}
    {% raw %}
    <style>
        /* Reset and Base Styles */
        * { box-sizing: border-box; margin: 0; padding: 0; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        @keyframes highlight-value {
            0%, 100% { transform: scale(1); color: #fff; }
            50% { transform: scale(1.05); color: #80deea; } /* Lighter cyan highlight */
        }
        .value-changed .card-value { animation: highlight-value 0.4s ease-out; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: #181a1f; color: #e0e0e0; line-height: 1.5;
            display: flex; flex-direction: column; min-height: 100vh; overflow-x: hidden;
        }

        /* Header */
        .app-header {
            background: #21242a; padding: 10px 25px; display: flex; align-items: center;
            border-bottom: 1px solid #3a3d4a; position: sticky; top: 0; z-index: 10;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2); flex-wrap: wrap;
        }
        .logo { display: flex; align-items: center; margin-right: 20px; color: #00bcd4; /* Color for SVG */ }
        .logo svg { margin-right: 8px; }
        .logo-text-main { font-weight: 700; font-size: 1.4em; letter-spacing: 1px; color: #fff;}
        .logo-text-sub { font-size: 0.45em; color: #a0a0a0; text-transform: uppercase; line-height: 1; display: block; font-weight: normal; letter-spacing: 0.5px; margin-top: -2px;}
        .main-title { flex-grow: 1; text-align: center; font-size: 1.2em; font-weight: 500; color: #c5c5c5; margin: 5px 15px; }
        .status-indicator { font-size: 0.95em; font-weight: 500; margin: 5px 0; text-align: right; min-width: 150px; transition: color 0.3s ease; }
        .status-indicator.live { color: #4caf50; } /* Green */
        .status-indicator.error { color: #f44336; font-weight: bold; } /* Red */
        .status-indicator.stale { color: #ff9800; } /* Orange */
        .status-indicator.fetching { color: #03a9f4; } /* Blue */

        /* Main Content Grid */
        .main-content {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); /* Responsive grid */
            gap: 20px;
            padding: 25px;
            flex-grow: 1;
        }

        /* Card Styles */
        .status-card {
            border-radius: 8px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
            overflow: hidden; display: flex; flex-direction: column;
            color: #ffffff; border: 1px solid rgba(255, 255, 255, 0.08);
            animation: fadeIn 0.5s ease-out forwards;
            background-color: #2a2d35; /* Default background */
            transition: background-color 0.3s ease, transform 0.2s ease;
        }
        .status-card:hover { transform: translateY(-3px); box-shadow: 0 6px 16px rgba(0, 0, 0, 0.3); }

        /* Semantic background colors with gradients */
        .bg-pending { background: linear-gradient(135deg, #ffb74d, #ffa726); } /* Orange */
        .bg-processing { background: linear-gradient(135deg, #64b5f6, #42a5f5); } /* Blue */
        .bg-failed { background: linear-gradient(135deg, #e57373, #ef5350); } /* Red */
        .bg-processed { background: linear-gradient(135deg, #81c784, #66bb6a); } /* Green */
        .bg-requests { background: linear-gradient(135deg, #7986cb, #5c6bc0); } /* Indigo */
        .bg-cpu { background: linear-gradient(135deg, #ba68c8, #ab47bc); } /* Purple */
        .bg-mem { background: linear-gradient(135deg, #4dd0e1, #26c6da); } /* Cyan */
        .bg-uptime { background: linear-gradient(135deg, #90a4ae, #78909c); } /* Blue Grey */

        .card-main-content { padding: 15px 20px 20px 20px; text-shadow: 1px 1px 2px rgba(0,0,0,0.2); text-align: center; flex-grow: 1; display: flex; flex-direction: column; justify-content: center; }
        .card-title { font-size: 0.8em; font-weight: 600; color: rgba(255, 255, 255, 0.85); margin-bottom: 10px; text-transform: uppercase; letter-spacing: 0.5px; }
        .card-value { font-size: 2.3em; font-weight: 700; line-height: 1; color: #ffffff; display: block; transition: transform 0.2s ease; }

        /* Chart Section */
        .charts-section {
             display: grid;
             grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); /* Responsive grid */
             gap: 20px;
             padding: 0 25px 25px 25px; /* Padding below cards */
        }
        .chart-card {
            background: #2a2d35; border-radius: 8px; padding: 20px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
            border: 1px solid rgba(255, 255, 255, 0.08);
            animation: fadeIn 0.6s ease-out forwards;
            display: flex; flex-direction: column; /* Ensure title and canvas stack */
        }
         .chart-title {
            font-size: 1em; font-weight: 600; color: #e0e0e0; margin-bottom: 15px; text-align: center;
         }
        .chart-container {
            height: 250px; /* Fixed height for charts */
            position: relative;
            flex-grow: 1; /* Allow chart container to fill space */
        }
        .chart-container canvas { display: block; width: 100%; height: 100%; }

        /* Footer */
        .app-footer { text-align: center; padding: 15px; margin-top: auto; font-size: 0.85em; color: #888; border-top: 1px solid #3a3d4a; background: #1f2128; }
        .app-footer #backend-status { font-weight: 500; display: block; margin-top: 5px; transition: color 0.3s ease;}
        .app-footer #backend-status.error { color: #f44336; font-weight: bold; }
        .app-footer #backend-status.success { color: #bdc3c7; } /* Subtle color for success */

        /* Responsive */
        @media (max-width: 768px) {
            .main-content, .charts-section { padding: 15px; gap: 15px; }
            .app-header { padding: 8px 15px; flex-direction: column; align-items: flex-start; }
            .main-title { text-align: left; margin: 8px 0; }
            .status-indicator { align-self: flex-end; margin-top: -25px; } /* Adjust positioning */
            .card-value { font-size: 2em; }
            .charts-section { grid-template-columns: 1fr; } /* Single column charts */
        }
         @media (max-width: 480px) {
             .card-value { font-size: 1.8em; }
             .main-content { grid-template-columns: 1fr 1fr; } /* 2 columns on small */
         }
    </style>
    {% endraw %}
    {# ***** END RAW BLOCK FOR CSS ***** #}

</head>
<body>

    <header class="app-header">
         <div class="logo">
            <svg width="25" height="25" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M8.33331 25L41.6666 8.33331L75 25L41.6666 41.6666L8.33331 25Z" stroke="currentColor" stroke-width="10"/>
                <path d="M8.33331 75L41.6666 58.3333L75 75L41.6666 91.6666L8.33331 75Z" stroke="currentColor" stroke-width="10"/>
                <path d="M8.33331 50H75" stroke="currentColor" stroke-width="10"/>
            </svg>
            <div>
                <span class="logo-text-main">API</span>
                <span class="logo-text-sub">Metrics Dashboard</span>
            </div>
        </div>
        <h1 class="main-title">Live System Status</h1>
        <div id="status-indicator" class="status-indicator stale">Initializing...</div>
    </header>

    <main class="main-content" id="metric-cards">
        <!-- Cards dynamically updated by JS - add relevant bg class -->
        <div class="status-card bg-pending" id="card-pending-msgs"><div class="card-main-content"><div class="card-title">Pending Msgs</div><div class="card-value">--</div></div></div>
        <div class="status-card bg-processing" id="card-processing-msgs"><div class="card-main-content"><div class="card-title">Processing Msgs</div><div class="card-value">--</div></div></div>
        <div class="status-card bg-failed" id="card-failed-msgs"><div class="card-main-content"><div class="card-title">Failed Msgs</div><div class="card-value">--</div></div></div>
        <div class="status-card bg-processed" id="card-processed-msgs"><div class="card-main-content"><div class="card-title">Processed Msgs</div><div class="card-value">--</div></div></div>
        <div class="status-card bg-requests" id="card-total-requests"><div class="card-main-content"><div class="card-title">Total Reqs</div><div class="card-value">--</div></div></div>
        <div class="status-card bg-cpu" id="card-process-cpu"><div class="card-main-content"><div class="card-title">Process CPU %</div><div class="card-value">--</div></div></div>
        <div class="status-card bg-mem" id="card-process-mem"><div class="card-main-content"><div class="card-title">Process Mem (MB)</div><div class="card-value">--</div></div></div>
        <div class="status-card bg-uptime" id="card-uptime"><div class="card-main-content"><div class="card-title">Uptime</div><div class="card-value">--</div></div></div>
    </main>

    <section class="charts-section">
        <!-- Chart Canvases -->
        <div class="chart-card">
            <div class="chart-title">📈 Requests / Interval (Last <span id="req-chart-points">N</span> points)</div>
            <div class="chart-container"><canvas id="requestsChart"></canvas></div>
        </div>
        <div class="chart-card">
            <div class="chart-title">✉️ Message Status (Last <span id="msg-chart-points">N</span> points)</div>
            <div class="chart-container"><canvas id="messageStatusChart"></canvas></div>
        </div>
        <div class="chart-card">
            <div class="chart-title">⚙️ Performance (Last <span id="perf-chart-points">N</span> points)</div>
            <div class="chart-container"><canvas id="performanceChart"></canvas></div>
        </div>
        <div class="chart-card">
            <div class="chart-title">🛣️ Requests by Route (Current Totals)</div>
            <div class="chart-container"><canvas id="requestsByRouteChart"></canvas></div>
        </div>
         <div class="chart-card">
            <div class="chart-title">🚦 Requests by Status Code (Current Totals)</div>
            <div class="chart-container"><canvas id="requestsByStatusChart"></canvas></div>
        </div>
    </section>

    <footer class="app-footer">
        Real-time API Metrics Dashboard
        <span id="backend-status" class="success">Initializing...</span>
    </footer>

    {# ***** START RAW BLOCK FOR JAVASCRIPT ***** #}
    {% raw %}
    <script>
        // --- CONFIGURATION (Injected by Flask) ---
        // Use 'const' for variables that don't change after init
        const DASHBOARD_DATA_URL = '/api/dashboard_data';
        const POLLING_INTERVAL_MS = {{ FETCH_INTERVAL_SECONDS * 1000 }};
        const MAX_CHART_HISTORY = {{ MAX_CHART_HISTORY }};

        // --- GLOBAL STATE ---
        let chartInstances = {}; // Use let as it's reassigned during init
        let fetchDataIntervalId = null;
        let lastKnownError = null; // Track the last error shown to avoid redundant updates

        // --- DOM Elements Cache (Ensure caching happens after DOM is loaded) ---
        let statusIndicator = null;
        let backendStatusSpan = null;
        let cardValueElements = {};

        function cacheDOMElements() {
            statusIndicator = document.getElementById('status-indicator');
            backendStatusSpan = document.getElementById('backend-status');
            cardValueElements = {
                pendingMsgs: document.querySelector('#card-pending-msgs .card-value'),
                processingMsgs: document.querySelector('#card-processing-msgs .card-value'),
                failedMsgs: document.querySelector('#card-failed-msgs .card-value'),
                processedMsgs: document.querySelector('#card-processed-msgs .card-value'),
                totalRequests: document.querySelector('#card-total-requests .card-value'),
                processCpu: document.querySelector('#card-process-cpu .card-value'),
                processMem: document.querySelector('#card-process-mem .card-value'),
                uptime: document.querySelector('#card-uptime .card-value')
            };
             // Update chart point display spans dynamically based on config
             try { // Add try-catch for robustness if elements don't exist
                document.getElementById('req-chart-points').textContent = MAX_CHART_HISTORY;
                document.getElementById('msg-chart-points').textContent = MAX_CHART_HISTORY;
                document.getElementById('perf-chart-points').textContent = MAX_CHART_HISTORY;
             } catch (e) {
                console.warn("Could not update chart point labels:", e);
             }
        }


        // --- UTILITY FUNCTIONS ---
        function formatNumber(num) {
            // Ensure input is treated as a number, return '--' if invalid
            const number = Number(num);
            return (num === null || num === undefined || isNaN(number)) ? '--' : number.toLocaleString('pt-BR');
        }
        function formatPercentage(num) {
            const number = Number(num);
            return (num === null || num === undefined || isNaN(number)) ? '--' : number.toFixed(1) + '%';
        }
        function formatMemory(num) {
            const number = Number(num);
            return (num === null || num === undefined || isNaN(number)) ? '--' : number.toFixed(1) + ' MB';
        }
        // Updates a card's value, formats it, and adds a highlight effect
        function updateCardValue(element, newValue, formatter = formatNumber) {
            if (!element) return; // Guard against null elements
            const formattedValue = formatter(newValue);
            // Only update if the value actually changed or if it's currently '--'
            if (element.textContent !== formattedValue) {
                element.textContent = formattedValue;
                const card = element.closest('.status-card'); // Find the parent card
                if (card) {
                    // Simple highlight: quick class toggle
                    card.classList.add('value-changed');
                    setTimeout(() => card.classList.remove('value-changed'), 400); // Remove after animation duration
                    // // Reflow method (more complex, sometimes needed for rapid changes)
                    // card.classList.remove('value-changed');
                    // void card.offsetWidth; // Force reflow
                    // card.classList.add('value-changed');
                }
            }
        }
        // Generates colors for categorical charts, cycling through a base palette
        function generateColors(count) {
             // Palette adjusted for better contrast/variety
             const baseColors = ['#64b5f6', '#81c784', '#ffb74d', '#e57373', '#ba68c8', '#4dd0e1', '#fff176', '#7986cb', '#a1887f', '#90a4ae'];
             const colors = [];
             for (let i = 0; i < count; i++) {
                 colors.push(baseColors[i % baseColors.length]);
             }
             return colors;
         }
        // Resets card values to '--' (e.g., on initial load or error)
         function clearCards() {
             Object.values(cardValueElements).forEach(el => { if(el) el.textContent = '--'; });
         }
        // Function to safely update chart data, handling potential missing datasets
        function updateChartData(chartInstance, newLabels, newDatasetsData) {
            // Guard clauses
            if (!chartInstance || !chartInstance.data || !chartInstance.data.datasets) {
                console.warn("Attempted to update non-existent or invalid chart instance.");
                return;
            }
            if (!Array.isArray(newLabels)) newLabels = [];
            if (!Array.isArray(newDatasetsData)) newDatasetsData = [];

            chartInstance.data.labels = newLabels;

            // Update each dataset present in the chart instance
            chartInstance.data.datasets.forEach((dataset, index) => {
                // Check if corresponding new data exists
                if (newDatasetsData[index] !== undefined && Array.isArray(newDatasetsData[index])) {
                    dataset.data = newDatasetsData[index];

                    // Update colors dynamically ONLY for categorical charts needing it (like bar/doughnut)
                    // Check if backgroundColor is an array (indicating categorical)
                    if (chartInstance.config.type === 'bar' || chartInstance.config.type === 'doughnut') {
                       if(Array.isArray(dataset.backgroundColor)) {
                           dataset.backgroundColor = generateColors(newDatasetsData[index].length);
                       }
                       // You might need similar logic for borderColor if needed
                    }
                } else {
                    // If no new data for this dataset index, clear it
                    dataset.data = [];
                    console.warn(`No data provided for dataset index ${index} in chart. Clearing it.`);
                }
            });

            // Update the chart without animation for smoother live updates
            chartInstance.update('none');
        }


        // --- CHART INITIALIZATION ---
         function initializeCharts() {
             console.log("Initializing charts...");
             // Set Chart.js defaults for better appearance
             Chart.defaults.color = '#e0e0e0'; // Default font color for scales, legends, tooltips
             Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.1)'; // Default grid line color

             const defaultLineOptions = {
                 responsive: true, maintainAspectRatio: false, // Essential for resizing
                 animation: { duration: 250, easing: 'linear' }, // Subtle animation
                 plugins: {
                     legend: {
                         display: true, position: 'bottom',
                         labels: { padding: 10, boxWidth: 12, font: { size: 11 } }
                     },
                     tooltip: {
                         mode: 'index', intersect: false, // Show tooltips for all datasets at that index
                         backgroundColor: 'rgba(0,0,0,0.8)', titleFont: { weight: 'bold' },
                         bodySpacing: 4, padding: 8, boxPadding: 4
                     }
                 },
                 scales: {
                     x: {
                         ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 10, font: { size: 10 } },
                         grid: { display: true } // Keep X grid lines subtle
                     },
                     y: { // Default Y axis (can be overridden)
                         ticks: { beginAtZero: true, font: { size: 10 }, precision: 0 }, // Default to whole numbers if possible
                         grid: { display: true, color: 'rgba(255, 255, 255, 0.08)' } // Lighter Y grid
                     }
                 },
                 elements: {
                     line: { tension: 0.2, borderWidth: 1.5 }, // Slight curve, standard width
                     point: { radius: 0, hitRadius: 10, hoverRadius: 4 } // No points normally, larger hit area
                 },
                 interaction: { // Improve hover interaction
                     mode: 'nearest', axis: 'x', intersect: false
                 }
             };

             // Requests Chart (Line)
             const reqCtx = document.getElementById('requestsChart')?.getContext('2d');
             if (reqCtx) {
                 const reqOptions = JSON.parse(JSON.stringify(defaultLineOptions)); // Clone options
                 chartInstances.requests = new Chart(reqCtx, {
                     type: 'line',
                     data: { labels: [], datasets: [{
                         label: 'Requests/Interval', data: [],
                         borderColor: '#64b5f6', backgroundColor: 'rgba(100, 181, 246, 0.2)', fill: true
                     }] },
                     options: reqOptions
                 });
             } else { console.error("Canvas element #requestsChart not found"); }

             // Message Status Chart (Line)
             const msgCtx = document.getElementById('messageStatusChart')?.getContext('2d');
              if (msgCtx) {
                 const msgOptions = JSON.parse(JSON.stringify(defaultLineOptions)); // Clone options
                 msgOptions.elements.line.borderWidth = 2; // Make lines slightly thicker
                 chartInstances.messageStatus = new Chart(msgCtx, {
                     type: 'line',
                     data: { labels: [], datasets: [
                         { label: 'Pending', data: [], borderColor: '#ffb74d', fill: false }, // Orange
                         { label: 'Processing', data: [], borderColor: '#64b5f6', fill: false }, // Blue
                         { label: 'Failed', data: [], borderColor: '#e57373', fill: false },    // Red
                         { label: 'Processed', data: [], borderColor: '#81c784', fill: false }  // Green
                     ] },
                     options: msgOptions
                 });
             } else { console.error("Canvas element #messageStatusChart not found"); }

             // Performance Chart (Line with Multi-Axis)
             const perfCtx = document.getElementById('performanceChart')?.getContext('2d');
              if (perfCtx) {
                 const perfOptions = JSON.parse(JSON.stringify(defaultLineOptions)); // Clone options
                 // Define specific Y axes
                 perfOptions.scales.yCpu = { // Use unique IDs
                     type: 'linear', position: 'left', title: { display: true, text: 'CPU (%)', color: '#ba68c8' },
                     ticks: { color: '#ba68c8', suggestedMax: 100, beginAtZero: true, precision: 1 }, // Allow decimals
                     grid: { drawOnChartArea: true } // Primary axis grid
                 };
                 perfOptions.scales.yMem = { // Use unique IDs
                     type: 'linear', position: 'right', title: { display: true, text: 'Memory (MB)', color: '#4dd0e1' },
                     ticks: { color: '#4dd0e1', beginAtZero: true, precision: 1 }, // Allow decimals
                     grid: { drawOnChartArea: false }, // No grid for secondary axis
                 };
                 delete perfOptions.scales.y; // Remove the default 'y' scale

                 chartInstances.performance = new Chart(perfCtx, {
                     type: 'line',
                     data: { labels: [], datasets: [
                         { label: 'Process CPU %', data: [], borderColor: '#ba68c8', fill: false, yAxisID: 'yCpu' }, // Purple
                         { label: 'Process Mem (MB)', data: [], borderColor: '#4dd0e1', fill: false, yAxisID: 'yMem' } // Cyan
                     ] },
                     options: perfOptions
                 });
             } else { console.error("Canvas element #performanceChart not found"); }

             // Default options for Bar/Doughnut
             const defaultCategoricalOptions = {
                 responsive: true, maintainAspectRatio: false,
                 plugins: {
                     legend: { display: true, position: 'bottom', labels: { padding: 10, boxWidth: 12, font: { size: 11 } } },
                     tooltip: { backgroundColor: 'rgba(0,0,0,0.8)', titleFont: { weight: 'bold' }, bodySpacing: 4, padding: 8, boxPadding: 4 }
                 }
             };

             // Requests by Route Chart (Horizontal Bar)
             const routeCtx = document.getElementById('requestsByRouteChart')?.getContext('2d');
             if (routeCtx) {
                 const routeOptions = JSON.parse(JSON.stringify(defaultCategoricalOptions)); // Clone options
                 routeOptions.indexAxis = 'y'; // Make bars horizontal
                 routeOptions.plugins.legend.display = false; // Hide legend (often too many items)
                 routeOptions.scales = {
                     x: { ticks: { precision: 0, beginAtZero: true }, grid: { color: 'rgba(255,255,255,0.08)' } }, // X axis = count
                     y: { ticks: { font: { size: 10 } }, grid: { display: false } } // Y axis = route name
                 };
                 chartInstances.requestsByRoute = new Chart(routeCtx, {
                     type: 'bar',
                     data: { labels: [], datasets: [{ label: 'Count', data: [], backgroundColor: [] }] }, // Colors generated dynamically
                     options: routeOptions
                 });
             } else { console.error("Canvas element #requestsByRouteChart not found"); }

             // Requests by Status Chart (Doughnut)
             const statusCtx = document.getElementById('requestsByStatusChart')?.getContext('2d');
              if (statusCtx) {
                 const statusOptions = JSON.parse(JSON.stringify(defaultCategoricalOptions));
                 statusOptions.plugins.legend.position = 'right'; // Position legend for doughnut
                 chartInstances.requestsByStatus = new Chart(statusCtx, {
                     type: 'doughnut',
                     data: { labels: [], datasets: [{
                         label: 'Count', data: [], backgroundColor: [], borderWidth: 1, hoverOffset: 8
                     }] }, // Colors generated dynamically
                     options: statusOptions
                 });
             } else { console.error("Canvas element #requestsByStatusChart not found"); }

             console.log("Charts initialized.");
         }


        // --- DATA FETCHING AND PROCESSING ---
        async function fetchData() {
            // Indicate fetching visually, but only if not already showing an error
            if (statusIndicator && !statusIndicator.classList.contains('error')) {
                 statusIndicator.textContent = 'Fetching...';
                 statusIndicator.className = 'status-indicator fetching';
            }
            console.debug(`[${new Date().toLocaleTimeString()}] Fetching data from ${DASHBOARD_DATA_URL}`);

            try {
                const response = await fetch(DASHBOARD_DATA_URL);

                // Handle HTTP errors from the dashboard server itself
                if (!response.ok) {
                    let errorMsg = `Error fetching dashboard data: ${response.status} ${response.statusText}`;
                    try {
                        // Attempt to get more detail from the response body
                        const errorData = await response.json();
                        errorMsg += ` - ${errorData.error || JSON.stringify(errorData)}`;
                    } catch (e) { /* Ignore if response body is not JSON or empty */ }
                    throw new Error(errorMsg); // Throw to be caught by the outer catch block
                }

                const data = await response.json();
                // console.debug("Raw dashboard data received:", JSON.stringify(data, null, 2)); // Verbose logging if needed

                // --- Process the received data ---
                // Check if the dashboard backend reported an error *during its API fetch*
                if (data.error) {
                    if (lastKnownError !== data.error) { // Avoid spamming the same error
                        console.error("Dashboard backend reported API fetch error:", data.error);
                        if (statusIndicator) {
                            statusIndicator.textContent = 'API Error';
                            statusIndicator.className = 'status-indicator error';
                        }
                        if (backendStatusSpan) {
                            backendStatusSpan.textContent = `API Error: ${data.error}`;
                            backendStatusSpan.className = 'error';
                        }
                        lastKnownError = data.error;
                        // Decide whether to clear data or leave stale data visible
                        // clearCards(); // Option: Clear cards on backend error
                    }
                // Check if the stats object is missing or empty
                } else if (!data.latest_stats || Object.keys(data.latest_stats).length === 0) {
                    if (lastKnownError !== "Empty stats data") { // Avoid spamming
                        console.warn("Dashboard backend returned empty 'latest_stats' data.");
                        if (statusIndicator) {
                            statusIndicator.textContent = 'No Data';
                            statusIndicator.className = 'status-indicator stale';
                        }
                         const fetchTime = data.last_successful_fetch ? new Date(data.last_successful_fetch).toLocaleString('pt-BR') : 'Never';
                        if (backendStatusSpan) {
                            backendStatusSpan.textContent = `No stats received. Last API fetch: ${fetchTime}`;
                            backendStatusSpan.className = 'error'; // Style as error/warning
                        }
                        lastKnownError = "Empty stats data";
                        clearCards(); // Clear cards if no valid data received
                        // Optionally clear charts too
                        Object.values(chartInstances).forEach(chart => updateChartData(chart, [], []));
                    }
                } else {
                    // --- Success Case: Valid data received ---
                    if (statusIndicator) {
                        statusIndicator.textContent = 'Live';
                        statusIndicator.className = 'status-indicator live';
                    }
                    const fetchTime = data.last_successful_fetch ? new Date(data.last_successful_fetch).toLocaleString('pt-BR') : 'Never';
                    if (backendStatusSpan) {
                        backendStatusSpan.textContent = `Last API fetch: ${fetchTime}`;
                        backendStatusSpan.className = 'success';
                    }
                    updateDashboardUI(data); // Update UI with fresh data
                    lastKnownError = null; // Clear the tracked error on success
                }

            } catch (error) {
                // --- Error fetching data *from the dashboard server itself* ---
                if (lastKnownError !== error.message) { // Avoid spamming
                    console.error("Error fetching or processing dashboard data from /api/dashboard_data:", error);
                    if (statusIndicator) {
                        statusIndicator.textContent = 'Dashboard Error';
                        statusIndicator.className = 'status-indicator error';
                    }
                    if (backendStatusSpan) {
                        backendStatusSpan.textContent = `Dashboard Fetch Error: ${error.message}`;
                        backendStatusSpan.className = 'error';
                    }
                    lastKnownError = error.message;
                    clearCards(); // Clear cards on dashboard fetch error
                    // Optionally clear charts too
                    Object.values(chartInstances).forEach(chart => updateChartData(chart, [], []));
                 }
            }
        }

        // --- UI UPDATE FUNCTION ---
        function updateDashboardUI(data) {
            // Basic validation already done in fetchData, but double-check core objects
            if (!data?.latest_stats || !data?.history) {
                 console.warn("updateDashboardUI called with incomplete data structure. Aborting UI update.");
                 return;
            }

            const stats = data.latest_stats;
            const history = data.history;
            const timeLabels = history.time_labels || []; // Use default empty array

            // console.debug("Updating UI with stats:", stats); // Uncomment for detailed debug

            // --- Update Cards ---
            updateCardValue(cardValueElements.pendingMsgs, stats.messages_pending);
            updateCardValue(cardValueElements.processingMsgs, stats.messages_processing);
            updateCardValue(cardValueElements.failedMsgs, stats.messages_failed);
            updateCardValue(cardValueElements.processedMsgs, stats.messages_processed);
            updateCardValue(cardValueElements.totalRequests, stats.requests_total);
            // Use optional chaining (?.) and nullish coalescing (??) for safer access
            updateCardValue(cardValueElements.processCpu, stats.system?.process_cpu_percent ?? null, formatPercentage);
            updateCardValue(cardValueElements.processMem, stats.system?.process_memory_mb ?? null, formatMemory);
            updateCardValue(cardValueElements.uptime, stats.uptime_human, (val) => val || '--');

            // --- Update Line Charts ---
            updateChartData(chartInstances.requests, timeLabels, [
                history.request_history || []
            ]);
            updateChartData(chartInstances.messageStatus, timeLabels, [
                history.message_status?.pending || [],
                history.message_status?.processing || [],
                history.message_status?.failed || [],
                history.message_status?.processed || []
            ]);
             updateChartData(chartInstances.performance, timeLabels, [
                history.performance?.cpu || [],
                history.performance?.memory || []
             ]);

            // --- Update Categorical Charts (Bar and Doughnut) ---
            // Requests by Route (Horizontal Bar)
            if (chartInstances.requestsByRoute) {
                const routes = stats.requests_by_route || {};
                // Sort routes alphabetically for consistent order
                const routeLabels = Object.keys(routes).sort();
                const routeData = routeLabels.map(route => {
                    // Sum counts for all methods under this route path
                    const methods = routes[route] || {};
                    return Object.values(methods).reduce((sum, count) => sum + (Number(count) || 0), 0);
                });
                 updateChartData(chartInstances.requestsByRoute, routeLabels, [routeData]);
            }

             // Requests by Status (Doughnut)
             if (chartInstances.requestsByStatus) {
                const statuses = stats.requests_by_status || {};
                // Sort status codes numerically for logical chart order
                const statusLabels = Object.keys(statuses).sort((a, b) => Number(a) - Number(b));
                const statusData = statusLabels.map(status => statuses[status] || 0);
                updateChartData(chartInstances.requestsByStatus, statusLabels, [statusData]);
            }
            // console.debug("UI update complete."); // Uncomment for detailed debug
        }

        // --- Initialization ---
        document.addEventListener('DOMContentLoaded', () => {
            console.log("DOM Loaded. Initializing dashboard.");
            cacheDOMElements(); // Cache elements now that DOM is ready
            initializeCharts(); // Setup chart structures
            clearCards(); // Set initial card values to '--'
            fetchData(); // Perform the first data fetch immediately

            // Start polling for new data after the first fetch attempt
            if (fetchDataIntervalId) clearInterval(fetchDataIntervalId); // Clear previous interval if any
            fetchDataIntervalId = setInterval(fetchData, POLLING_INTERVAL_MS);
            console.log(`Started polling data every ${POLLING_INTERVAL_MS / 1000} seconds.`);
        });

    </script>
    {% endraw %}
    {# ***** END RAW BLOCK FOR JAVASCRIPT ***** #}

</body>
</html>
"""


# --- Flask Routes ---

@app.route('/')
def serve_dashboard():
    """Serve the main dashboard HTML page, rendering the template string."""
    logger.info("Serving dashboard HTML page.")
    try:
        # Render the HTML, injecting configuration variables into the JS template sections
        return render_template_string(
            HTML_CONTENT,
            FETCH_INTERVAL_SECONDS=FETCH_INTERVAL_SECONDS,
            MAX_CHART_HISTORY=MAX_CHART_HISTORY
        )
    except Exception as e:
        # Catch potential Jinja errors during rendering itself
        logger.error(f"Error rendering dashboard template: {e}", exc_info=True)
        # Return a simple error page if template rendering fails
        return f"<h1>Internal Server Error</h1><p>Failed to render dashboard template: {e}</p>", 500

@app.route('/api/dashboard_data')
def get_dashboard_data():
    """Endpoint for the frontend JavaScript to fetch the collected data."""
    logger.debug("Request received for /api/dashboard_data")
    with data_lock:
        # Create a snapshot of the current state to avoid holding the lock during serialization
        # Ensure all deques are converted to lists for JSON compatibility
        try:
            data_to_send = {
                # Shallow copy is usually fine for dicts of primitives/strings/numbers
                "latest_stats": app_state.get("latest_stats", {}).copy(),
                "history": {
                    "time_labels": list(app_state.get("time_labels", [])),
                    "request_history": list(app_state.get("request_history", [])),
                    "message_status": {
                        "pending": list(app_state.get("message_status_history", {}).get("pending", [])),
                        "processing": list(app_state.get("message_status_history", {}).get("processing", [])),
                        "failed": list(app_state.get("message_status_history", {}).get("failed", [])),
                        "processed": list(app_state.get("message_status_history", {}).get("processed", [])),
                    },
                    "performance": {
                        "cpu": list(app_state.get("performance_history", {}).get("cpu", [])),
                        "memory": list(app_state.get("performance_history", {}).get("memory", [])),
                    }
                },
                "last_successful_fetch": app_state.get("last_successful_fetch"),
                "error": app_state.get("last_error") # Pass the last known error (if any)
            }
        except Exception as e:
            logger.error(f"Error preparing data for /api/dashboard_data: {e}", exc_info=True)
            return jsonify({"error": "Failed to prepare data", "detail": str(e)}), 500

    # logger.debug(f"Returning dashboard data: {json.dumps(data_to_send)}") # Be careful logging large data
    return jsonify(data_to_send)

# --- Inicialização ---
if __name__ == '__main__':
    # Disable warnings for insecure HTTPS requests (verify=False) made by this script
    # ONLY use this in development with self-signed certs you trust.
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        logger.warning("SSL certificate verification is disabled for API requests made by this dashboard. THIS IS INSECURE FOR PRODUCTION.")
    except ImportError:
        logger.warning("urllib3 not found, cannot disable InsecureRequestWarning.")
    except Exception as e:
        logger.warning(f"Could not disable urllib3 warnings: {e}")

    # Start the scheduler thread in the background
    # daemon=True ensures the thread exits when the main Flask process exits
    scheduler_thread = threading.Thread(target=run_scheduler, name="SchedulerThread", daemon=True)
    scheduler_thread.start()

    logger.info(f"Starting Dashboard server on http://0.0.0.0:{DASHBOARD_PORT}")
    logger.info(f"Attempting to fetch data from API at {API_BASE_URL} every {FETCH_INTERVAL_SECONDS} seconds.")

    # Run the Flask app
    # Use debug=False in production to avoid security risks and duplicate scheduler runs
    # Disable reloader when using threads to avoid issues.
    # Consider using a production-ready WSGI server like Gunicorn or Waitress.
    # Example using Waitress (install first: pip install waitress):
    # from waitress import serve
    # serve(app, host='0.0.0.0', port=DASHBOARD_PORT)
    try:
        logger.info("Using Flask's built-in development server. Not recommended for production.")
        app.run(host='0.0.0.0', port=DASHBOARD_PORT, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        logger.info("Dashboard server stopped by user (Ctrl+C).")
    except Exception as e:
        logger.critical(f"Dashboard server failed to start or crashed: {e}", exc_info=True)