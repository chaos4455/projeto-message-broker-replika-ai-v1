# dashboard_server.py
import os
import time
import threading
import logging
from collections import deque
from threading import Lock
from datetime import datetime, timezone
import json # For handling potential decoding errors

import requests # To make requests to the main API
import schedule # To schedule data collection
from flask import Flask, Response, jsonify, render_template_string
from flask_cors import CORS

# --- Configuration ---
DASHBOARD_PORT = 8333
# Default to HTTPS and the simplified API port
API_BASE_URL = os.environ.get("API_BASE_URL", "https://127.0.0.1:8777")
API_STATS_URL = f"{API_BASE_URL}/stats"
API_LOGIN_URL = f"{API_BASE_URL}/login"

# Credentials for the dashboard to access the main API
# !!! Use environment variables in production !!!
API_USERNAME = os.environ.get("API_USER", "admin") # Default 'admin'
API_PASSWORD = os.environ.get("API_PASS", "admin") # Default 'admin'

FETCH_INTERVAL_SECONDS = 5 # Data collection interval
MAX_CHART_HISTORY = 60 # History points for line charts

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('DashboardServer') # Specific name

# --- Global State and Control ---
app_state = {
    "latest_stats": {},
    "last_error": None,
    "last_successful_fetch": None,
    "api_token": None, # Store only the access token
    "refresh_token": None, # Kept for potential future use if API adds refresh logic
    "login_needed": True,
    "is_fetching": False,
    # History for charts
    "time_labels": deque(maxlen=MAX_CHART_HISTORY),
    "request_history": deque(maxlen=MAX_CHART_HISTORY), # Deltas per interval
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
    "previous_total_requests": 0 # For calculating delta
}
data_lock = Lock() # Protect concurrent access to app_state

# --- Collection and Processing Functions ---

def login_to_api():
    """Attempts to log in to the main API and stores the tokens."""
    global app_state
    logger.info(f"Attempting login to API at {API_LOGIN_URL}...")
    try:
        login_data = {'username': API_USERNAME, 'password': API_PASSWORD}
        # IMPORTANT: Disable SSL verification ONLY for local dev with self-signed certs
        response = requests.post(API_LOGIN_URL, data=login_data, verify=False, timeout=10)
        response.raise_for_status() # Raise exception for HTTP 4xx/5xx errors

        token_data = response.json()
        if "access_token" in token_data and "refresh_token" in token_data:
            with data_lock:
                app_state["api_token"] = token_data["access_token"]
                app_state["refresh_token"] = token_data["refresh_token"]
                app_state["login_needed"] = False
                app_state["last_error"] = None # Clear previous login error
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
        try: # Try to get more details
            if e.response is not None:
                content_type = e.response.headers.get('Content-Type', '')
                if 'application/json' in content_type:
                   error_json = e.response.json()
                   error_detail += f" - Detail: {error_json.get('detail', error_json)}"
                else: error_detail += f" - Response: {e.response.text[:200]}"
        except Exception: pass
        logger.error(f"API login failed ({error_detail}): {e}")
        with data_lock:
            app_state["last_error"] = f"Login request failed: {e}"
            app_state["api_token"] = None
            app_state["refresh_token"] = None
            app_state["login_needed"] = True
        return False
    except json.JSONDecodeError as e:
        response_text = getattr(e.response, 'text', 'N/A')
        logger.error(f"API login failed: Could not decode JSON. Response: {response_text[:500]}")
        with data_lock:
            app_state["last_error"] = "Login response not valid JSON"
            app_state["api_token"] = None; app_state["refresh_token"] = None; app_state["login_needed"] = True
        return False
    except Exception as e:
        logger.error(f"Unexpected error during API login: {e}", exc_info=True)
        with data_lock:
            app_state["last_error"] = f"Unexpected login error: {e}"
            app_state["api_token"] = None; app_state["refresh_token"] = None; app_state["login_needed"] = True
        return False

def fetch_api_data():
    """Fetches /stats data from the main API, handles authentication."""
    global app_state

    with data_lock: # Prevent concurrent fetches
        if app_state.get("is_fetching", False):
            logger.debug("Fetch skipped, already fetching.")
            return
        app_state["is_fetching"] = True
        token = app_state["api_token"]
        login_needed = app_state["login_needed"]

    logger.debug("Starting data fetch cycle...")
    try:
        # --- Handle Authentication ---
        if login_needed or not token:
            logger.warning("Login required or token missing, attempting login...")
            if not login_to_api():
                logger.error("Fetch cycle aborted: login failed.")
                with data_lock:
                     if app_state["last_error"] is None: app_state["last_error"] = "Login required but failed"
                return
            with data_lock: # Re-fetch token after successful login
                token = app_state["api_token"]
                if not token: # Should not happen if login_to_api returned True
                     logger.error("CRITICAL: Token missing after successful login. Aborting.")
                     app_state["last_error"] = "Internal dashboard error: Token lost."
                     return

        # --- Fetch Stats Data ---
        logger.debug(f"Fetching stats from {API_STATS_URL}...")
        headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/json'}
        try:
            # Disable SSL verification ONLY for local dev
            response = requests.get(API_STATS_URL, headers=headers, verify=False, timeout=10)

            # Check for auth errors first -> triggers re-login next cycle
            if response.status_code in [401, 403]:
                logger.warning(f"API auth error ({response.status_code}) fetching stats. Forcing re-login next cycle.")
                with data_lock:
                    app_state["api_token"] = None
                    app_state["login_needed"] = True
                    app_state["last_error"] = f"API Auth error ({response.status_code}). Re-login needed."
                return # Abort this cycle

            response.raise_for_status() # Check for other HTTP errors (5xx, 404 etc.)

            # ---- Process Successful Response ----
            try:
                stats = response.json()
                now = datetime.now(timezone.utc)
                logger.debug("Stats received successfully.")

                with data_lock: # Update state under lock
                    app_state["latest_stats"] = stats
                    app_state["last_successful_fetch"] = now.isoformat()
                    app_state["last_error"] = None # Clear errors on success

                    # Update history deques
                    current_time_label = now.strftime("%H:%M:%S")
                    app_state["time_labels"].append(current_time_label)

                    # Calculate request delta
                    current_total = stats.get("requests_total")
                    delta = 0
                    if isinstance(current_total, int):
                        prev_total = app_state["previous_total_requests"]
                        delta = max(0, current_total - (prev_total if isinstance(prev_total, int) else 0))
                        app_state["previous_total_requests"] = current_total
                    else: logger.warning("`requests_total` missing or invalid in stats.")
                    app_state["request_history"].append(delta)

                    # Message history (safe access with .get)
                    app_state["message_status_history"]["pending"].append(stats.get("messages_pending", 0))
                    app_state["message_status_history"]["processing"].append(stats.get("messages_processing", 0))
                    app_state["message_status_history"]["failed"].append(stats.get("messages_failed", 0))
                    app_state["message_status_history"]["processed"].append(stats.get("messages_processed", 0))

                    # Performance history (safe access)
                    sys_stats = stats.get("system", {})
                    cpu = sys_stats.get("process_cpu_percent")
                    mem = sys_stats.get("process_memory_mb")
                    app_state["performance_history"]["cpu"].append(cpu if isinstance(cpu, (int, float)) else 0)
                    app_state["performance_history"]["memory"].append(mem if isinstance(mem, (int, float)) else 0)

                logger.debug("Dashboard state updated.")

            except json.JSONDecodeError as e:
                 logger.error(f"Failed to decode JSON from API /stats: {e}. Response: {response.text[:500]}")
                 with data_lock: app_state["last_error"] = "API /stats response not valid JSON"
            except Exception as processing_e:
                logger.error(f"Error processing received stats: {processing_e}", exc_info=True)
                with data_lock: app_state["last_error"] = f"Error processing stats: {processing_e}"

        # --- Handle Request Errors ---
        except requests.exceptions.Timeout:
            logger.error("API /stats request timed out.")
            with data_lock: app_state["last_error"] = "API Timeout fetching stats"
        except requests.exceptions.ConnectionError as e:
            logger.error(f"API /stats connection error: {e}")
            with data_lock: app_state["last_error"] = f"API Connection Error: {e}"
        except requests.exceptions.RequestException as e:
            status_code = getattr(e.response, 'status_code', 'N/A')
            logger.error(f"API /stats request failed (Status: {status_code}): {e}")
            error_detail = f"API Request Failed: {e}"
            try:
                if e.response is not None: error_detail += f" - Response: {e.response.text[:200]}"
            except Exception: pass
            with data_lock:
                 # Avoid overwriting a more specific auth error
                 if app_state.get("last_error") is None or "Auth error" not in app_state["last_error"]:
                     app_state["last_error"] = error_detail

    except Exception as outer_e:
        logger.error(f"Unexpected error during fetch setup: {outer_e}", exc_info=True)
        with data_lock: app_state["last_error"] = f"Unexpected Fetch Error: {outer_e}"
    finally:
        with data_lock: app_state["is_fetching"] = False # Ensure flag is reset


def run_scheduler():
    """Runs the scheduler loop in a separate thread."""
    logger.info("Scheduler thread started.")
    try: # Perform an initial fetch immediately
        fetch_api_data()
    except Exception as e: logger.error(f"Error during initial fetch: {e}", exc_info=True)

    schedule.every(FETCH_INTERVAL_SECONDS).seconds.do(fetch_api_data)
    while True:
        try: schedule.run_pending()
        except Exception as e: logger.error(f"Error in scheduler loop: {e}", exc_info=True)
        time.sleep(1)

# --- Flask App ---
app = Flask(__name__)
app.logger.handlers = logger.handlers # Use configured logger
app.logger.setLevel(logger.level)
CORS(app) # Enable CORS

# --- HTML Content ---
# Uses Jinja templating for configuration injection.
# IMPORTANT: {% raw %} blocks are critical for CSS and JS containing {{ }} syntax.
HTML_CONTENT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Metrics Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><path d=%22M8.3 25L41.7 8.3L75 25L41.7 41.7L8.3 25Z%22 stroke=%22%2300bcd4%22 stroke-width=%2210%22 fill=%22none%22/><path d=%22M8.3 75L41.7 58.3L75 75L41.7 91.7L8.3 75Z%22 stroke=%22%2300bcd4%22 stroke-width=%2210%22 fill=%22none%22/><path d=%22M8.3 50H75%22 stroke=%22%2300bcd4%22 stroke-width=%2210%22 fill=%22none%22/></svg>">

    {# ***** START RAW BLOCK FOR CSS ***** #}
    {% raw %}
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        @keyframes highlight-value {
            0%, 100% { transform: scale(1); color: #fff; }
            50% { transform: scale(1.05); color: #80deea; }
        }
        .value-changed .card-value { animation: highlight-value 0.4s ease-out; }
        body { font-family: system-ui, sans-serif; background: #181a1f; color: #e0e0e0; line-height: 1.5; display: flex; flex-direction: column; min-height: 100vh; overflow-x: hidden; }
        .app-header { background: #21242a; padding: 10px 25px; display: flex; align-items: center; border-bottom: 1px solid #3a3d4a; position: sticky; top: 0; z-index: 10; box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2); flex-wrap: wrap; }
        .logo { display: flex; align-items: center; margin-right: 20px; color: #00bcd4; }
        .logo svg { margin-right: 8px; }
        .logo-text-main { font-weight: 700; font-size: 1.4em; letter-spacing: 1px; color: #fff;}
        .logo-text-sub { font-size: 0.45em; color: #a0a0a0; text-transform: uppercase; line-height: 1; display: block; font-weight: normal; letter-spacing: 0.5px; margin-top: -2px;}
        .main-title { flex-grow: 1; text-align: center; font-size: 1.2em; font-weight: 500; color: #c5c5c5; margin: 5px 15px; }
        .status-indicator { font-size: 0.95em; font-weight: 500; margin: 5px 0; text-align: right; min-width: 150px; transition: color 0.3s ease; }
        .status-indicator.live { color: #4caf50; }
        .status-indicator.error { color: #f44336; font-weight: bold; }
        .status-indicator.stale { color: #ff9800; }
        .status-indicator.fetching { color: #03a9f4; }
        .main-content { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 25px; flex-grow: 1; }
        .status-card { border-radius: 8px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25); overflow: hidden; display: flex; flex-direction: column; color: #ffffff; border: 1px solid rgba(255, 255, 255, 0.08); animation: fadeIn 0.5s ease-out forwards; background-color: #2a2d35; transition: background-color 0.3s ease, transform 0.2s ease; }
        .status-card:hover { transform: translateY(-3px); box-shadow: 0 6px 16px rgba(0, 0, 0, 0.3); }
        .bg-pending { background: linear-gradient(135deg, #ffb74d, #ffa726); }
        .bg-processing { background: linear-gradient(135deg, #64b5f6, #42a5f5); }
        .bg-failed { background: linear-gradient(135deg, #e57373, #ef5350); }
        .bg-processed { background: linear-gradient(135deg, #81c784, #66bb6a); }
        .bg-requests { background: linear-gradient(135deg, #7986cb, #5c6bc0); }
        .bg-cpu { background: linear-gradient(135deg, #ba68c8, #ab47bc); }
        .bg-mem { background: linear-gradient(135deg, #4dd0e1, #26c6da); }
        .bg-uptime { background: linear-gradient(135deg, #90a4ae, #78909c); }
        .card-main-content { padding: 15px 20px 20px 20px; text-shadow: 1px 1px 2px rgba(0,0,0,0.2); text-align: center; flex-grow: 1; display: flex; flex-direction: column; justify-content: center; }
        .card-title { font-size: 0.8em; font-weight: 600; color: rgba(255, 255, 255, 0.85); margin-bottom: 10px; text-transform: uppercase; letter-spacing: 0.5px; }
        .card-value { font-size: 2.3em; font-weight: 700; line-height: 1; color: #ffffff; display: block; transition: transform 0.2s ease; }
        .charts-section { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 20px; padding: 0 25px 25px 25px; }
        .chart-card { background: #2a2d35; border-radius: 8px; padding: 20px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25); border: 1px solid rgba(255, 255, 255, 0.08); animation: fadeIn 0.6s ease-out forwards; display: flex; flex-direction: column; }
        .chart-title { font-size: 1em; font-weight: 600; color: #e0e0e0; margin-bottom: 15px; text-align: center; }
        .chart-container { height: 250px; position: relative; flex-grow: 1; }
        .chart-container canvas { display: block; width: 100%; height: 100%; }
        .app-footer { text-align: center; padding: 15px; margin-top: auto; font-size: 0.85em; color: #888; border-top: 1px solid #3a3d4a; background: #1f2128; }
        .app-footer #backend-status { font-weight: 500; display: block; margin-top: 5px; transition: color 0.3s ease;}
        .app-footer #backend-status.error { color: #f44336; font-weight: bold; }
        .app-footer #backend-status.success { color: #bdc3c7; }
        @media (max-width: 768px) {
            .main-content, .charts-section { padding: 15px; gap: 15px; }
            .app-header { padding: 8px 15px; flex-direction: column; align-items: flex-start; }
            .main-title { text-align: left; margin: 8px 0; }
            .status-indicator { align-self: flex-end; margin-top: -25px; }
            .card-value { font-size: 2em; }
            .charts-section { grid-template-columns: 1fr; }
        }
        @media (max-width: 480px) {
             .card-value { font-size: 1.8em; }
             .main-content { grid-template-columns: 1fr 1fr; }
         }
    </style>
    {% endraw %}
    {# ***** END RAW BLOCK FOR CSS ***** #}
</head>
<body>
    <header class="app-header">
         <div class="logo">
            <svg width="25" height="25" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M8.3 25L41.7 8.3L75 25L41.7 41.7L8.3 25Z" stroke="currentColor" stroke-width="10"/><path d="M8.3 75L41.7 58.3L75 75L41.7 91.7L8.3 75Z" stroke="currentColor" stroke-width="10"/><path d="M8.3 50H75" stroke="currentColor" stroke-width="10"/></svg>
            <div><span class="logo-text-main">API</span><span class="logo-text-sub">Metrics Dashboard</span></div>
        </div>
        <h1 class="main-title">Live System Status</h1>
        <div id="status-indicator" class="status-indicator stale">Initializing...</div>
    </header>

    <main class="main-content" id="metric-cards">
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

    <script>
        // --- Injected Variables (Jinja WILL process this part) ---
        const DASHBOARD_DATA_URL = '/api/dashboard_data';
        // Use config values injected by Flask
        const POLLING_INTERVAL_MS = {{ FETCH_INTERVAL_SECONDS * 1000 }}; // NOT in raw
        const MAX_CHART_HISTORY = {{ MAX_CHART_HISTORY }};             // NOT in raw

        // --- Start Raw Block (Jinja IGNORES the rest) ---
        {% raw %}

        // --- The rest of your original JavaScript logic ---
        let chartInstances = {};
        let fetchDataIntervalId = null;
        let lastKnownError = null;
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
             try {
                // NOTE: MAX_CHART_HISTORY is available here because it was defined above
                document.getElementById('req-chart-points').textContent = MAX_CHART_HISTORY;
                document.getElementById('msg-chart-points').textContent = MAX_CHART_HISTORY;
                document.getElementById('perf-chart-points').textContent = MAX_CHART_HISTORY;
             } catch (e) { console.warn("Could not update chart point labels:", e); }
        }

        function formatNumber(num) { return (num === null || num === undefined || isNaN(Number(num))) ? '--' : Number(num).toLocaleString(); }
        function formatPercentage(num) { return (num === null || num === undefined || isNaN(Number(num))) ? '--' : Number(num).toFixed(1) + '%'; }
        function formatMemory(num) { return (num === null || num === undefined || isNaN(Number(num))) ? '--' : Number(num).toFixed(1) + ' MB'; }

        function updateCardValue(element, newValue, formatter = formatNumber) {
            if (!element) return;
            const formattedValue = formatter(newValue);
            if (element.textContent !== formattedValue) {
                element.textContent = formattedValue;
                const card = element.closest('.status-card');
                if (card) { card.classList.add('value-changed'); setTimeout(() => card.classList.remove('value-changed'), 400); }
            }
        }

        function generateColors(count) {
             const baseColors = ['#64b5f6', '#81c784', '#ffb74d', '#e57373', '#ba68c8', '#4dd0e1', '#fff176', '#7986cb', '#a1887f', '#90a4ae'];
             return Array.from({ length: count }, (_, i) => baseColors[i % baseColors.length]);
         }

         function clearCards() { Object.values(cardValueElements).forEach(el => { if(el) el.textContent = '--'; }); }

        function updateChartData(chartInstance, newLabels = [], newDatasetsData = []) {
            if (!chartInstance?.data?.datasets) return;
            chartInstance.data.labels = newLabels;
            chartInstance.data.datasets.forEach((dataset, index) => {
                // Ensure we have data for this dataset, default to empty array if not
                const dataForDataset = (Array.isArray(newDatasetsData) && Array.isArray(newDatasetsData[index]))
                                       ? newDatasetsData[index] : [];
                dataset.data = dataForDataset;

                // Regenerate colors for bar/doughnut if data length changes
                if ((chartInstance.config.type === 'bar' || chartInstance.config.type === 'doughnut') && Array.isArray(dataset.backgroundColor)) {
                   dataset.backgroundColor = generateColors(dataForDataset.length);
                   // Also handle potential borderColor array for doughnuts
                   if (Array.isArray(dataset.borderColor)) {
                       dataset.borderColor = dataset.backgroundColor.map(color => color.replace(')', ', 0.7)').replace('rgb', 'rgba')); // Example border adjustment
                   }
                }
            });
            chartInstance.update('none'); // Use 'none' for smoother updates without full re-animation
        }

        function initializeCharts() {
             console.log("Initializing charts...");
             Chart.defaults.color = '#e0e0e0';
             Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.1)';

             const defaultLineOptions = { responsive: true, maintainAspectRatio: false, animation: { duration: 250 }, plugins: { legend: { position: 'bottom', labels: { padding: 10, boxWidth: 12, font: { size: 11 } } }, tooltip: { mode: 'index', intersect: false, backgroundColor: 'rgba(0,0,0,0.8)' } }, scales: { x: { ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 10, font: { size: 10 } } }, y: { ticks: { beginAtZero: true, font: { size: 10 }, precision: 0 }, grid: { color: 'rgba(255, 255, 255, 0.08)' } } }, elements: { line: { tension: 0.2, borderWidth: 1.5 }, point: { radius: 0, hitRadius: 10, hoverRadius: 4 } }, interaction: { mode: 'nearest', axis: 'x', intersect: false } };
             const defaultCategoricalOptions = { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { padding: 10, boxWidth: 12, font: { size: 11 } } }, tooltip: { backgroundColor: 'rgba(0,0,0,0.8)' } } };

             // Requests Chart (Line)
             const reqCtx = document.getElementById('requestsChart')?.getContext('2d');
             if (reqCtx) chartInstances.requests = new Chart(reqCtx, { type: 'line', data: { labels: [], datasets: [{ label: 'Requests/Interval', data: [], borderColor: '#64b5f6', backgroundColor: 'rgba(100, 181, 246, 0.2)', fill: true }] }, options: JSON.parse(JSON.stringify(defaultLineOptions)) }); else console.error("#requestsChart not found");

             // Message Status Chart (Line)
             const msgCtx = document.getElementById('messageStatusChart')?.getContext('2d');
             if (msgCtx) { const opts = JSON.parse(JSON.stringify(defaultLineOptions)); opts.elements.line.borderWidth = 2; chartInstances.messageStatus = new Chart(msgCtx, { type: 'line', data: { labels: [], datasets: [ { label: 'Pending', data: [], borderColor: '#ffb74d', fill: false }, { label: 'Processing', data: [], borderColor: '#64b5f6', fill: false }, { label: 'Failed', data: [], borderColor: '#e57373', fill: false }, { label: 'Processed', data: [], borderColor: '#81c784', fill: false } ] }, options: opts }); } else console.error("#messageStatusChart not found");

             // Performance Chart (Line, Multi-Axis)
             const perfCtx = document.getElementById('performanceChart')?.getContext('2d');
             if (perfCtx) { const opts = JSON.parse(JSON.stringify(defaultLineOptions)); opts.scales.yCpu = { type: 'linear', position: 'left', title: { display: true, text: 'CPU (%)', color: '#ba68c8' }, ticks: { color: '#ba68c8', suggestedMax: 100, beginAtZero: true, precision: 1 } }; opts.scales.yMem = { type: 'linear', position: 'right', title: { display: true, text: 'Memory (MB)', color: '#4dd0e1' }, ticks: { color: '#4dd0e1', beginAtZero: true, precision: 1 }, grid: { drawOnChartArea: false } }; delete opts.scales.y; chartInstances.performance = new Chart(perfCtx, { type: 'line', data: { labels: [], datasets: [ { label: 'Process CPU %', data: [], borderColor: '#ba68c8', fill: false, yAxisID: 'yCpu' }, { label: 'Process Mem (MB)', data: [], borderColor: '#4dd0e1', fill: false, yAxisID: 'yMem' } ] }, options: opts }); } else console.error("#performanceChart not found");

             // Requests by Route (Bar)
             const routeCtx = document.getElementById('requestsByRouteChart')?.getContext('2d');
             if (routeCtx) { const opts = JSON.parse(JSON.stringify(defaultCategoricalOptions)); opts.indexAxis = 'y'; opts.plugins.legend.display = false; opts.scales = { x: { ticks: { precision: 0, beginAtZero: true }, grid: { color: 'rgba(255,255,255,0.08)' } }, y: { ticks: { font: { size: 10 } }, grid: { display: false } } }; chartInstances.requestsByRoute = new Chart(routeCtx, { type: 'bar', data: { labels: [], datasets: [{ label: 'Count', data: [], backgroundColor: [] }] }, options: opts }); } else console.error("#requestsByRouteChart not found");

             // Requests by Status (Doughnut)
             const statusCtx = document.getElementById('requestsByStatusChart')?.getContext('2d');
             if (statusCtx) { const opts = JSON.parse(JSON.stringify(defaultCategoricalOptions)); opts.plugins.legend.position = 'right'; chartInstances.requestsByStatus = new Chart(statusCtx, { type: 'doughnut', data: { labels: [], datasets: [{ label: 'Count', data: [], backgroundColor: [], borderWidth: 1, hoverOffset: 8 }] }, options: opts }); } else console.error("#requestsByStatusChart not found");
             console.log("Charts initialized.");
         }

        async function fetchData() {
            if (statusIndicator && !statusIndicator.classList.contains('error')) {
                 statusIndicator.textContent = 'Fetching...'; statusIndicator.className = 'status-indicator fetching';
            }
            console.debug(`[${new Date().toLocaleTimeString()}] Fetching ${DASHBOARD_DATA_URL}`);

            try {
                const response = await fetch(DASHBOARD_DATA_URL);
                if (!response.ok) {
                    let errorMsg = `Error fetching dashboard data: ${response.status} ${response.statusText}`;
                    try { const errData = await response.json(); errorMsg += ` - ${errData.error || JSON.stringify(errData)}`; } catch (e) {}
                    throw new Error(errorMsg);
                }
                const data = await response.json();

                if (data.error) { // Check if backend reported an API fetch error
                    if (lastKnownError !== data.error) {
                        console.error("Dashboard backend reported API error:", data.error);
                        if (statusIndicator) { statusIndicator.textContent = 'API Error'; statusIndicator.className = 'status-indicator error'; }
                        if (backendStatusSpan) { backendStatusSpan.textContent = `API Error: ${data.error}`; backendStatusSpan.className = 'error'; }
                        lastKnownError = data.error;
                        // clearCards(); // Optional: clear cards on backend error
                    }
                } else if (!data.latest_stats || Object.keys(data.latest_stats).length === 0) { // Check for empty stats
                     if (lastKnownError !== "Empty stats data") {
                        console.warn("Dashboard backend returned empty 'latest_stats'.");
                        if (statusIndicator) { statusIndicator.textContent = 'No Data'; statusIndicator.className = 'status-indicator stale'; }
                        const fetchTime = data.last_successful_fetch ? new Date(data.last_successful_fetch).toLocaleString() : 'Never';
                        if (backendStatusSpan) { backendStatusSpan.textContent = `No API stats received. Last fetch: ${fetchTime}`; backendStatusSpan.className = 'error'; }
                        lastKnownError = "Empty stats data";
                        clearCards();
                        Object.values(chartInstances).forEach(chart => updateChartData(chart)); // Clear charts
                    }
                } else { // Success Case
                    if (statusIndicator) { statusIndicator.textContent = 'Live'; statusIndicator.className = 'status-indicator live'; }
                    const fetchTime = data.last_successful_fetch ? new Date(data.last_successful_fetch).toLocaleString() : 'Never';
                    if (backendStatusSpan) { backendStatusSpan.textContent = `Last API fetch: ${fetchTime}`; backendStatusSpan.className = 'success'; }
                    updateDashboardUI(data);
                    lastKnownError = null;
                }
            } catch (error) { // Error fetching from dashboard server itself
                if (lastKnownError !== error.message) {
                    console.error("Error fetching or processing dashboard data:", error);
                    if (statusIndicator) { statusIndicator.textContent = 'Dashboard Error'; statusIndicator.className = 'status-indicator error'; }
                    if (backendStatusSpan) { backendStatusSpan.textContent = `Dashboard Fetch Error: ${error.message}`; backendStatusSpan.className = 'error'; }
                    lastKnownError = error.message;
                    clearCards();
                    Object.values(chartInstances).forEach(chart => updateChartData(chart)); // Clear charts
                 }
            }
        }

        function updateDashboardUI(data) {
             // Defend against incomplete data structures
            if (!data || typeof data !== 'object') { console.error("updateDashboardUI called with invalid data:", data); return; }
            const stats = data.latest_stats || {};
            const history = data.history || {};
            const timeLabels = history.time_labels || [];

            // Update Cards
            updateCardValue(cardValueElements.pendingMsgs, stats.messages_pending);
            updateCardValue(cardValueElements.processingMsgs, stats.messages_processing);
            updateCardValue(cardValueElements.failedMsgs, stats.messages_failed);
            updateCardValue(cardValueElements.processedMsgs, stats.messages_processed);
            updateCardValue(cardValueElements.totalRequests, stats.requests_total);
            // Access system stats safely
            const systemStats = stats.system || {};
            updateCardValue(cardValueElements.processCpu, systemStats.process_cpu_percent ?? null, formatPercentage);
            updateCardValue(cardValueElements.processMem, systemStats.process_memory_mb ?? null, formatMemory);
            updateCardValue(cardValueElements.uptime, stats.uptime_human, (val) => val || '--');

            // Update Line Charts (ensure history data exists)
            const requestHistory = history.request_history || [];
            const messageStatusHistory = history.message_status || {};
            const performanceHistory = history.performance || {};

            updateChartData(chartInstances.requests, timeLabels, [ requestHistory ]);
            updateChartData(chartInstances.messageStatus, timeLabels, [
                messageStatusHistory.pending || [], messageStatusHistory.processing || [],
                messageStatusHistory.failed || [], messageStatusHistory.processed || []
            ]);
            updateChartData(chartInstances.performance, timeLabels, [
                performanceHistory.cpu || [], performanceHistory.memory || []
            ]);

            // Update Categorical Charts
            if (chartInstances.requestsByRoute) {
                const routes = stats.requests_by_route || {};
                const routeLabels = Object.keys(routes).sort();
                // Ensure routes[r] exists and is an object before using Object.values
                const routeData = routeLabels.map(r => typeof routes[r] === 'object' && routes[r] !== null ? Object.values(routes[r]).reduce((s, c) => s + (Number(c) || 0), 0) : 0);
                updateChartData(chartInstances.requestsByRoute, routeLabels, [routeData]);
            }
            if (chartInstances.requestsByStatus) {
                const statuses = stats.requests_by_status || {};
                const statusLabels = Object.keys(statuses).sort((a, b) => Number(a) - Number(b));
                const statusData = statusLabels.map(s => statuses[s] || 0);
                updateChartData(chartInstances.requestsByStatus, statusLabels, [statusData]);
            }
        }

        document.addEventListener('DOMContentLoaded', () => {
            console.log("DOM Loaded. Initializing dashboard.");
            cacheDOMElements();
            initializeCharts();
            clearCards();
            fetchData(); // Initial fetch
            if (fetchDataIntervalId) clearInterval(fetchDataIntervalId);
             // NOTE: POLLING_INTERVAL_MS is available here because it was defined above
            fetchDataIntervalId = setInterval(fetchData, POLLING_INTERVAL_MS);
            console.log(`Polling data every ${POLLING_INTERVAL_MS / 1000}s.`);
        });

        // --- End Raw Block ---
        {% endraw %}
    </script>
</body>
</html>
"""


# --- Flask Routes ---

@app.route('/')
def serve_dashboard():
    """Serve the main dashboard HTML page."""
    logger.info("Serving dashboard HTML page.")
    try:
        # Render HTML, injecting Python config into JS template parts
        return render_template_string(
            HTML_CONTENT,
            FETCH_INTERVAL_SECONDS=FETCH_INTERVAL_SECONDS,
            MAX_CHART_HISTORY=MAX_CHART_HISTORY
        )
    except Exception as e:
        logger.error(f"Error rendering dashboard template: {e}", exc_info=True)
        return f"<h1>Internal Server Error</h1><p>Failed to render template: {e}</p>", 500

@app.route('/api/dashboard_data')
def get_dashboard_data():
    """Endpoint for frontend JS to fetch collected data."""
    logger.debug("Request received for /api/dashboard_data")
    with data_lock:
        try:
            # Create snapshot, convert deques to lists for JSON
            data_to_send = {
                "latest_stats": app_state.get("latest_stats", {}).copy(),
                "history": {
                    "time_labels": list(app_state.get("time_labels", [])),
                    "request_history": list(app_state.get("request_history", [])),
                    "message_status": {k: list(v) for k, v in app_state.get("message_status_history", {}).items()},
                    "performance": {k: list(v) for k, v in app_state.get("performance_history", {}).items()}
                },
                "last_successful_fetch": app_state.get("last_successful_fetch"),
                "error": app_state.get("last_error") # Pass last known error
            }
        except Exception as e:
            logger.error(f"Error preparing data for /api/dashboard_data: {e}", exc_info=True)
            return jsonify({"error": "Failed to prepare data", "detail": str(e)}), 500
    return jsonify(data_to_send)

# --- Initialization ---
if __name__ == '__main__':
    # Optionally disable warnings for insecure HTTPS requests made by this script
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        logger.warning("SSL certificate verification disabled for API requests by dashboard. INSECURE FOR PRODUCTION.")
    except Exception as e: logger.warning(f"Could not disable urllib3 warnings: {e}")

    # Start the scheduler thread
    scheduler_thread = threading.Thread(target=run_scheduler, name="SchedulerThread", daemon=True)
    scheduler_thread.start()

    logger.info(f"Starting Dashboard server on http://0.0.0.0:{DASHBOARD_PORT}")
    logger.info(f"Fetching data from API ({API_BASE_URL}) every {FETCH_INTERVAL_SECONDS} seconds.")

    # Run Flask app (use a production server like Waitress/Gunicorn for real deployment)
    try:
        # from waitress import serve
        # logger.info("Starting server with Waitress...")
        # serve(app, host='0.0.0.0', port=DASHBOARD_PORT)
        logger.info("Using Flask's development server (use Waitress/Gunicorn for production).")
        app.run(host='0.0.0.0', port=DASHBOARD_PORT, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        logger.info("Dashboard server stopped.")
    except Exception as e:
        logger.critical(f"Dashboard server failed: {e}", exc_info=True)