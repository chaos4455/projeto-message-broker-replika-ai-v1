# dashboard_server_pro_enhanced.py
import os
import time
import threading
import logging
from collections import deque
from threading import Lock
from datetime import datetime, timezone, timedelta
import json
import math
from functools import wraps
import re
import random # For potential mock data if API isn't fully featured yet
import traceback # For detailed error logging

import requests
import schedule
from flask import Flask, Response, jsonify, render_template_string, request
from flask_cors import CORS
from markupsafe import Markup # For rendering HTML in info tables safely

# --- Configuration ---
DASHBOARD_PORT = 8333
API_BASE_URL = os.environ.get("API_BASE_URL", "https://127.0.0.1:8777").rstrip('/')
API_STATS_URL = f"{API_BASE_URL}/stats"
API_LOGIN_URL = f"{API_BASE_URL}/login"
API_QUEUES_URL = f"{API_BASE_URL}/queues"
API_LOGS_LIST_URL = f"{API_BASE_URL}/logs"
API_LOG_CONTENT_URL = f"{API_BASE_URL}/logs" # Endpoint like /logs/{filename}

API_USERNAME = os.environ.get("API_USER", "admin")
API_PASSWORD = os.environ.get("API_PASS", "admin")

FETCH_STATS_INTERVAL_SECONDS = 5
FETCH_QUEUES_INTERVAL_SECONDS = 15
FETCH_LOGLIST_INTERVAL_SECONDS = 60
FETCH_LOGCONTENT_INTERVAL_SECONDS = 30 # Default auto-refresh

MAX_CHART_HISTORY = 360 # ~30 mins at 5s interval (adjust as needed for performance/memory)
LOG_CHUNK_SIZE = 250 # Lines per log fetch (adjust based on typical line length/performance)
REQUESTS_TIMEOUT = 15 # Slightly longer timeout for potentially slower APIs
MAX_LOG_LINES_MEMORY = 5000 # Limit memory usage for logs deque

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(threadName)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('BrokerDashPro')
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("schedule").setLevel(logging.WARNING)
logging.getLogger('werkzeug').setLevel(logging.WARNING) # Quieter Flask dev server logs

# --- Global State ---
class DashboardState:
    def __init__(self, max_history, log_chunk_size):
        self.lock = Lock()
        self.latest_stats = {}
        self.latest_queues = []
        self.last_api_error = None
        self.last_successful_stats_fetch = None
        self.last_successful_queues_fetch = None
        self.last_successful_loglist_fetch = None
        self.last_successful_logcontent_fetch = None
        self.api_access_token = None
        self.login_needed = True
        self.server_start_time = datetime.now(timezone.utc)

        self.is_fetching_stats = False
        self.is_fetching_queues = False
        self.is_fetching_loglist = False
        self.is_fetching_logcontent = False

        # History Deques
        self.max_history = max_history
        self.time_labels = deque(maxlen=max_history)
        self.request_rate_history = deque(maxlen=max_history)
        self.processed_rate_history = deque(maxlen=max_history)
        self.failed_rate_history = deque(maxlen=max_history)
        self.message_status_history = {
            "pending": deque(maxlen=max_history),
            "processing": deque(maxlen=max_history),
            "failed": deque(maxlen=max_history),
            "processed": deque(maxlen=max_history)
        }
        self.performance_history = {
            "process_cpu": deque(maxlen=max_history),
            "process_memory": deque(maxlen=max_history),
            "system_cpu": deque(maxlen=max_history),
            "system_memory": deque(maxlen=max_history)
        }
        self.http_error_rate_history = deque(maxlen=max_history) # % 4xx/5xx

        # Rate Calculation State
        self.previous_total_requests = 0
        self.previous_total_processed = 0
        self.previous_total_failed = 0
        self.previous_req_by_status = {}
        self.last_calc_timestamp = None

        # Log State
        self.log_chunk_size = log_chunk_size
        self.available_log_files = []
        self.current_log_filename = None
        self.log_lines = deque(maxlen=MAX_LOG_LINES_MEMORY) # Apply memory limit directly
        self.log_next_fetch_start_line = None # For fetching older lines (line number *after* the last fetched older block)
        self.log_fetch_error = None
        self.log_auto_refresh_enabled = True

    def _update_rate_history(self, history_deque, current_total, previous_total_attr, interval_seconds):
        current_val = current_total if isinstance(current_total, (int, float)) else 0
        prev_val = getattr(self, previous_total_attr, 0)
        delta = max(0, current_val - prev_val)
        rate = delta / interval_seconds if interval_seconds > 0 else 0
        history_deque.append(round(rate, 2)) # Store rate per second
        setattr(self, previous_total_attr, current_val)

    def _update_http_error_rate(self, current_req_by_status, interval_seconds):
        current_total = 0
        current_errors = 0
        # Ensure counts are integers
        safe_current_req_by_status = {}
        for status, count in current_req_by_status.items():
            try:
                code_str = str(status)
                count_val = int(count)
                safe_current_req_by_status[code_str] = count_val
                current_total += count_val
                if int(code_str) >= 400:
                    current_errors += count_val
            except (ValueError, TypeError):
                logger.warning(f"Invalid status/count in requests_by_status: {status}={count}")
                continue # Skip invalid entries

        prev_total = sum(self.previous_req_by_status.values())
        prev_errors = sum(count for status, count in self.previous_req_by_status.items() if int(status) >= 400)

        delta_total = max(0, current_total - prev_total)
        delta_errors = max(0, current_errors - prev_errors)

        # Calculate rate as percentage over the interval
        rate = (delta_errors / delta_total * 100) if delta_total > 0 else 0
        self.http_error_rate_history.append(round(rate, 2))
        self.previous_req_by_status = safe_current_req_by_status # Store the cleaned dictionary

    def update_stats_history(self, stats):
        now = datetime.now(timezone.utc)
        now_label = now.strftime("%H:%M:%S")

        # Calculate actual interval for rate calculation
        interval = 0
        if self.last_calc_timestamp:
            interval = (now - self.last_calc_timestamp).total_seconds()
        self.last_calc_timestamp = now

        # Only add history if interval is reasonable (avoid spikes on startup/gaps)
        if interval > 0.1:
            self.time_labels.append(now_label)

            # Calculate rates (requests/sec)
            self._update_rate_history(self.request_rate_history, stats.get("requests_total"), "previous_total_requests", interval)
            self._update_rate_history(self.processed_rate_history, stats.get("messages_processed"), "previous_total_processed", interval)
            self._update_rate_history(self.failed_rate_history, stats.get("messages_failed"), "previous_total_failed", interval)

            # Message Counts (absolute values)
            for status in ["pending", "processing", "failed", "processed"]:
                self.message_status_history[status].append(stats.get(f"messages_{status}", 0))

            # Performance Metrics (%)
            sys_stats = stats.get("system", {})
            self.performance_history["process_cpu"].append(round(safe_float(sys_stats.get("process_cpu_percent")), 2))
            self.performance_history["process_memory"].append(round(safe_float(sys_stats.get("process_memory_mb")), 2)) # Keep as MB for card, but use % for chart if available
            self.performance_history["system_cpu"].append(round(safe_float(sys_stats.get("cpu_percent")), 2))
            self.performance_history["system_memory"].append(round(safe_float(sys_stats.get("memory_percent")), 2))

            # HTTP Error Rate (%)
            self._update_http_error_rate(stats.get("requests_by_status", {}), interval)

    def update_error(self, error_message, error_type="generic"):
        with self.lock:
            timestamp = datetime.now(timezone.utc).isoformat()
            self.last_api_error = {"message": str(error_message), "type": error_type, "timestamp": timestamp}
            logger.error(f"API Error ({error_type}): {error_message}")

    def clear_error(self, error_type="generic"):
        with self.lock:
            # Clear only if the *current* error matches the type being cleared
            if self.last_api_error and self.last_api_error.get("type") == error_type:
                self.last_api_error = None
                logger.info(f"Cleared API error of type: {error_type}")

    def needs_login(self):
        with self.lock: return self.login_needed or not self.api_access_token
    def get_token(self):
        with self.lock: return self.api_access_token
    def set_token(self, token):
        with self.lock:
            self.api_access_token = token
            self.login_needed = False
            self.clear_error("auth") # Clear auth errors on successful login/token set
            logger.info("API token set successfully.")
    def invalidate_token(self, reason="Authentication failed"):
        with self.lock:
            self.api_access_token = None
            self.login_needed = True
            self.update_error(reason, "auth") # Log auth error when invalidating
            logger.warning(f"API token invalidated: {reason}")

    def get_snapshot_for_dashboard(self):
        with self.lock:
            # Create copies to avoid race conditions during JSON serialization
            return {
                "latest_stats": self.latest_stats.copy(),
                "latest_queues": self.latest_queues[:],
                "history": {
                    "time_labels": list(self.time_labels),
                    "request_rate_history": list(self.request_rate_history),
                    "processed_rate_history": list(self.processed_rate_history),
                    "failed_rate_history": list(self.failed_rate_history),
                    "message_status": {k: list(v) for k, v in self.message_status_history.items()},
                    "performance": {k: list(v) for k, v in self.performance_history.items()},
                    "http_error_rate_history": list(self.http_error_rate_history)
                },
                "current_log_filename": self.current_log_filename,
                "log_fetch_error": self.log_fetch_error,
                "last_successful_stats_fetch": self.last_successful_stats_fetch,
                "last_successful_queues_fetch": self.last_successful_queues_fetch,
                "last_api_error": self.last_api_error.copy() if self.last_api_error else None,
                "log_auto_refresh_enabled": self.log_auto_refresh_enabled,
                "available_log_files": self.available_log_files[:], # Send available logs list
                "log_next_fetch_start_line": self.log_next_fetch_start_line, # Let frontend know if "Load Older" is possible
                "server_start_time": self.server_start_time.isoformat()
            }

    def get_log_data_for_request(self):
         with self.lock:
             return {
                 "filename": self.current_log_filename,
                 "lines": list(self.log_lines), # Return current buffer
                 "next_fetch_start_line": self.log_next_fetch_start_line,
                 "log_fetch_error": self.log_fetch_error,
                 "last_successful_logcontent_fetch": self.last_successful_logcontent_fetch,
                 "log_auto_refresh_enabled": self.log_auto_refresh_enabled
             }

    def update_log_lines(self, new_lines, is_prepend=False, next_start_for_older=None):
         """Updates log lines, handling duplicates and max lines."""
         with self.lock:
            self.log_fetch_error = None # Clear error on successful fetch *before* processing
            self.last_successful_logcontent_fetch = datetime.now(timezone.utc).isoformat()
            self.log_next_fetch_start_line = next_start_for_older

            if not isinstance(new_lines, list):
                logger.warning("update_log_lines received non-list input.")
                return

            processed_count = 0
            if is_prepend: # Fetching older logs, append to the *end* of deque
                for line in new_lines: # Assume API returns older lines first
                    # Basic check if line already exists (heuristic based on message/timestamp)
                    # This isn't perfect but prevents obvious duplicates from overlapping fetches
                    exists = any(l.get('message') == line.get('message') and l.get('timestamp') == line.get('timestamp') for l in self.log_lines)
                    if not exists:
                        self.log_lines.append(line)
                        processed_count += 1
                logger.debug(f"Appended {processed_count}/{len(new_lines)} older unique log lines.")
            else: # Fetching latest logs, prepend to the *start* of deque
                # More robust duplicate check for recent lines
                existing_recent_hashes = set(hash(f"{l.get('timestamp')}_{l.get('message')}") for l in list(self.log_lines)[:LOG_CHUNK_SIZE*2]) # Check recent ~2 chunks
                unique_lines_to_add = []

                for line in new_lines: # Assume API returns newest lines first (e.g., from tail)
                    line_hash = hash(f"{line.get('timestamp')}_{line.get('message')}")
                    if line_hash not in existing_recent_hashes:
                        unique_lines_to_add.append(line)
                        existing_recent_hashes.add(line_hash) # Add new one to check against incoming batch

                for line in reversed(unique_lines_to_add): # Add unique lines newest first
                      self.log_lines.appendleft(line)
                      processed_count += 1
                logger.debug(f"Prepended {processed_count}/{len(new_lines)} new unique log lines.")

            # Max line limit is handled automatically by deque's maxlen

    def set_log_auto_refresh(self, enabled: bool):
        with self.lock:
            if self.log_auto_refresh_enabled != enabled:
                self.log_auto_refresh_enabled = enabled
                logger.info(f"Log auto-refresh set to: {enabled}")

# Initialize Global State
state = DashboardState(MAX_CHART_HISTORY, LOG_CHUNK_SIZE)

# --- Utilities ---
def safe_float(value, default=0.0):
    """Safely convert value to float."""
    try: return float(value) if value is not None else default
    except (ValueError, TypeError): return default

def format_timedelta_human(seconds):
    """Converts seconds into a human-readable string like 1d 2h 3m 4s."""
    if seconds is None or not isinstance(seconds, (int, float)) or seconds < 0: return "--"
    seconds = int(seconds)
    if seconds < 1: return "< 1 sec"
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days > 0: parts.append(f"{days}d")
    if hours > 0: parts.append(f"{hours}h")
    if minutes > 0: parts.append(f"{minutes}m")
    if secs > 0 or not parts: parts.append(f"{secs}s")
    return " ".join(parts)

def bytes_to_human(n_bytes, precision=1):
    """Converts bytes to a human-readable string (KB, MB, GB...)."""
    if n_bytes is None or not isinstance(n_bytes, (int, float)) or n_bytes < 0: return "--"
    n_bytes = int(n_bytes)
    if n_bytes == 0: return "0 B"
    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    power = min(int(math.log(n_bytes, 1024)), len(units) - 1) if n_bytes > 0 else 0
    value = n_bytes / (1024 ** power)
    return f"{value:.{precision}f} {units[power]}"

# --- API Error Handling Decorator ---
def handle_api_errors(error_scope="generic"):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            global state
            token = None # Define token outside the conditional block

            # --- Authentication Check ---
            if state.needs_login():
                logger.info(f"Login required for {func.__name__}, attempting login...")
                if not login_to_api():
                    logger.error(f"Aborting {func.__name__}: login failed.")
                    # Ensure an error is set if login fails
                    if not state.last_api_error or state.last_api_error.get("type") != "auth":
                       state.update_error("API login failed or credentials incorrect.", "auth")
                    return False # Indicate failure
                # After successful login, get the token
                token = state.get_token()
                if not token:
                    # This case should ideally not happen if login_to_api sets token correctly
                    logger.error(f"Internal dashboard error: Token missing after successful login attempt for {func.__name__}.")
                    state.update_error("Internal error: Token lost after login.", "internal")
                    return False
            else:
                token = state.get_token()
                if not token:
                     logger.error(f"Internal dashboard error: Token is unexpectedly None for {func.__name__} despite not needing login.")
                     state.update_error("Internal error: Token unexpectedly missing.", "internal")
                     state.invalidate_token("Token missing unexpectedly") # Force re-login next time
                     return False

            # --- Prepare Request ---
            headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/json'}
            # Disable SSL verification only for local addresses
            verify_ssl = not ("127.0.0.1" in API_BASE_URL or "localhost" in API_BASE_URL)

            # --- Execute API Call ---
            try:
                # Inject headers and verify_ssl into the decorated function's kwargs
                kwargs['headers'] = headers
                kwargs['verify_ssl'] = verify_ssl
                result = func(*args, **kwargs)

                # If the function executed and didn't raise an exception that implies success
                # Clear the specific error scope *if* the result indicates success (e.g., returns True or data)
                # The called function should return False or raise an exception on *logical* failure (e.g., 404 handled internally)
                if result is not False: # Check against explicit False return
                     state.clear_error(error_scope)
                return result # Pass back the result (could be data, True, False)

            # --- Error Handling ---
            except requests.exceptions.Timeout as e:
                state.update_error(f"API request timed out calling {func.__name__}", error_scope)
                logger.warning(f"Timeout during {func.__name__}: {e}")
            except requests.exceptions.SSLError as e:
                state.update_error(f"API SSL Error in {func.__name__}: {e}. Check certs/URL.", error_scope)
                logger.error(f"SSL Error during {func.__name__}: {e}")
            except requests.exceptions.ConnectionError as e:
                state.update_error(f"API Connection Error in {func.__name__}: {e}. Cannot reach {API_BASE_URL}", error_scope)
                logger.error(f"Connection Error during {func.__name__}: {e}")
            except requests.exceptions.HTTPError as e:
                status_code = getattr(e.response, 'status_code', 'N/A')
                response_text = ""
                try: response_text = e.response.text[:200] if e.response is not None else "N/A"
                except Exception: pass
                error_detail = f"API HTTP Error ({status_code}) in {func.__name__}: {e}. Response: {response_text}"

                if status_code in [401, 403]:
                    logger.warning(f"API auth error ({status_code}) calling {func.__name__}. Invalidating token.")
                    state.invalidate_token(f"API Auth error ({status_code}) calling {func.__name__}")
                else:
                    # Log other HTTP errors without invalidating token immediately
                    state.update_error(error_detail, error_scope)
                    logger.warning(error_detail) # Log as warning, might be transient
            except requests.exceptions.RequestException as e:
                state.update_error(f"General API Request Failed in {func.__name__}: {e}", error_scope)
                logger.error(f"RequestException during {func.__name__}: {e}")
            except json.JSONDecodeError as e:
                state.update_error(f"API response is not valid JSON in {func.__name__}. Error: {e}", error_scope)
                logger.error(f"JSONDecodeError during {func.__name__}: {e}")
            except Exception as e:
                logger.exception(f"Unexpected error during API call in {func.__name__}") # Log full traceback
                state.update_error(f"Unexpected error in {func.__name__}: {type(e).__name__} - {e}", "internal")

            return False # Indicate failure if any exception occurred
        return wrapper
    return decorator


# --- API Interaction ---
def login_to_api():
    """Attempts to login and sets the token in the state."""
    global state
    logger.info(f"Attempting login to API at {API_LOGIN_URL}...")
    verify_ssl = not ("127.0.0.1" in API_BASE_URL or "localhost" in API_BASE_URL)
    login_success = False
    try:
        response = requests.post(
            API_LOGIN_URL,
            data={'username': API_USERNAME, 'password': API_PASSWORD},
            verify=verify_ssl,
            timeout=REQUESTS_TIMEOUT
        )
        response.raise_for_status() # Raise HTTPError for bad status codes
        token_data = response.json()

        if "access_token" in token_data:
            state.set_token(token_data["access_token"]) # set_token handles logging and state change
            login_success = True
        else:
            logger.error("Login response received, but 'access_token' field is missing.")
            state.update_error("Login response missing 'access_token'", "auth")

    except requests.exceptions.HTTPError as e:
         status_code = getattr(e.response, 'status_code', 'N/A')
         detail = f"Status Code: {status_code}"
         try:
             if e.response is not None: detail += f" - Response: {e.response.json().get('detail', e.response.text[:100])}"
         except (json.JSONDecodeError, AttributeError):
             try: detail += f" - Response: {e.response.text[:100]}"
             except AttributeError: pass # No response object
         logger.error(f"API login HTTP error ({detail}): {e}")
         state.update_error(f"API login failed ({detail})", "auth")
    except requests.exceptions.RequestException as e:
        logger.error(f"API login request failed: {e}")
        state.update_error(f"API login failed: {e}", "auth")
    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode API login response: {e}")
        state.update_error("Invalid JSON response during login", "auth")
    except Exception as e:
        logger.exception("Unexpected error during API login")
        state.update_error(f"Unexpected login error: {e}", "internal")

    # Explicitly invalidate token if login wasn't successful
    if not login_success:
        state.invalidate_token("Login attempt failed")

    return login_success

@handle_api_errors(error_scope="stats")
def fetch_stats_data(headers, verify_ssl):
    """Fetches stats data from the API."""
    global state
    # Use a flag to prevent concurrent fetches of the same data
    with state.lock:
        if state.is_fetching_stats:
            logger.debug("Stats fetch skipped, already in progress.")
            return True # Not an error, just busy
        state.is_fetching_stats = True

    logger.debug("Fetching stats data...")
    success = False
    try:
        response = requests.get(API_STATS_URL, headers=headers, verify=verify_ssl, timeout=REQUESTS_TIMEOUT)
        response.raise_for_status() # Check for HTTP errors
        stats = response.json()

        # Basic validation of received stats
        if not isinstance(stats, dict) or not stats:
             logger.warning("Received empty or invalid stats data structure from API.")
             state.update_error("Received empty/invalid stats data", "stats")
             # Don't update history with bad data
        else:
            with state.lock:
                state.latest_stats = stats
                state.last_successful_stats_fetch = datetime.now(timezone.utc).isoformat()
                # Update history *after* successful fetch and storing latest_stats
                state.update_stats_history(stats)
            logger.info(f"Stats data updated successfully at {state.last_successful_stats_fetch}")
            success = True

    # Specific handling within the 'try' is now done by the decorator
    finally:
        # CRITICAL: Ensure the flag is reset regardless of success or failure
        with state.lock:
            state.is_fetching_stats = False

    return success # Decorator will return False if exceptions occurred

@handle_api_errors(error_scope="queues")
def fetch_queues_data(headers, verify_ssl):
    """Fetches queue data from the API."""
    global state
    with state.lock:
         if state.is_fetching_queues:
             logger.debug("Queues fetch skipped, already in progress.")
             return True
         state.is_fetching_queues = True

    logger.debug("Fetching queues data...")
    success = False
    try:
        response = requests.get(API_QUEUES_URL, headers=headers, verify=verify_ssl, timeout=REQUESTS_TIMEOUT)
        response.raise_for_status()
        queues = response.json()

        if not isinstance(queues, list):
            logger.warning("Received non-list data structure for queues from API.")
            state.update_error("Received invalid queues data format", "queues")
        else:
            with state.lock:
                # Sort queues alphabetically by name for consistent display
                state.latest_queues = sorted(queues, key=lambda q: q.get('name', ''))
                state.last_successful_queues_fetch = datetime.now(timezone.utc).isoformat()
            logger.info(f"Queues data updated successfully at {state.last_successful_queues_fetch} ({len(queues)} queues)")
            success = True
    finally:
        with state.lock:
            state.is_fetching_queues = False
    return success

@handle_api_errors(error_scope="loglist")
def fetch_log_list(headers, verify_ssl):
    """Fetches the list of available log files."""
    global state
    with state.lock:
        if state.is_fetching_loglist:
            logger.debug("Log list fetch skipped, already in progress.")
            return True
        state.is_fetching_loglist = True

    logger.debug("Fetching log file list...")
    success = False
    try:
        response = requests.get(API_LOGS_LIST_URL, headers=headers, verify=verify_ssl, timeout=REQUESTS_TIMEOUT)
        response.raise_for_status()
        log_data = response.json()

        # Expecting a dictionary with a 'log_files' key containing a list of strings
        if not isinstance(log_data, dict) or "log_files" not in log_data or not isinstance(log_data["log_files"], list):
            logger.warning("Received invalid log list data structure from API.")
            state.update_error("Invalid log list format from API", "loglist")
        else:
            files = sorted(log_data["log_files"], reverse=True) # Assume newest first is desirable
            with state.lock:
                state.available_log_files = files
                state.last_successful_loglist_fetch = datetime.now(timezone.utc).isoformat()
                logger.info(f"Log list updated at {state.last_successful_loglist_fetch}: {len(files)} files.")

                # Check if the currently viewed log file still exists
                current_file = state.current_log_filename
                if current_file and current_file not in files:
                    logger.warning(f"Current log file '{current_file}' no longer available in list. Clearing view.")
                    state.current_log_filename = None
                    state.log_lines.clear()
                    state.log_next_fetch_start_line = None
                    state.log_fetch_error = "Log file disappeared or was rotated." # Inform user

                # If no log file is selected and logs are available, select the newest one
                if not state.current_log_filename and files:
                    newest_log = files[0]
                    logger.info(f"No log selected, automatically selecting newest: '{newest_log}'")
                    state.current_log_filename = newest_log
                    state.log_lines.clear() # Clear old lines
                    state.log_next_fetch_start_line = None # Reset pagination
                    state.log_fetch_error = None # Clear previous errors
                    # Trigger an initial content fetch shortly after selecting the new file
                    schedule.clear('initial-log-content') # Clear previous one-time jobs if any
                    schedule.every(1).second.do(fetch_log_content_job, fetch_older=False).tag('initial-log-content')
            success = True
    finally:
        with state.lock:
            state.is_fetching_loglist = False
    return success

@handle_api_errors(error_scope="logcontent")
def fetch_log_content(filename, fetch_older=False, headers=None, verify_ssl=None):
    """Fetches log content chunks. Handles fetching newer or older lines."""
    global state
    if not filename:
        logger.warning("Log content fetch skipped: no filename specified.")
        # Don't set an error here, it's expected if no file is selected
        return False # Indicate skipped

    with state.lock:
        if state.is_fetching_logcontent:
            logger.debug(f"Log content fetch for '{filename}' skipped, already fetching.")
            return True # Not an error, just busy

        # --- Determine parameters ---
        params = {'limit': state.log_chunk_size} # Use limit for simplicity if API supports it
        start_line_for_older_request = None # Track the start line *requested* for older logs

        if fetch_older:
            older_start_num = state.log_next_fetch_start_line
            if older_start_num and older_start_num > 0:
                params['start'] = older_start_num
                params['end'] = older_start_num + state.log_chunk_size - 1
                del params['limit'] # Don't use limit if using start/end
                start_line_for_older_request = older_start_num
                logger.debug(f"Configured to fetch older logs for '{filename}' from line {older_start_num}")
            else:
                logger.info(f"Fetch older logs for '{filename}' skipped: No valid 'next_fetch_start_line' ({state.log_next_fetch_start_line}). Assuming beginning reached.")
                return True # Not an error, just nothing more to fetch older
        else: # Fetch latest using tail (or limit if API doesn't support tail)
            # Assuming API supports 'tail' or defaults to newest if no start/end
            params['tail'] = state.log_chunk_size
            if 'limit' in params: del params['limit'] # Prefer tail if available
            logger.debug(f"Configured to fetch latest logs for '{filename}' using tail/limit.")

        # --- Mark as fetching ---
        state.is_fetching_logcontent = True
        state.log_fetch_error = None # Clear previous fetch error before attempting

    logger.info(f"Fetching log content from API for '{filename}' with params: {params}")
    success = False
    try:
        # Construct URL: Ensure filename is URL-encoded
        # Simple encoding for basic cases, use urllib.parse.quote for robustness if needed
        safe_filename = filename.replace('/', '%2F')
        url = f"{API_LOG_CONTENT_URL}/{safe_filename}"

        response = requests.get(
            url,
            headers=headers,
            params=params,
            verify=verify_ssl,
            timeout=REQUESTS_TIMEOUT + 10 # Slightly longer timeout for log requests
        )
        response.raise_for_status() # Raises HTTPError for 4xx/5xx
        log_lines_received = response.json() # Assume API returns a list of log line objects/strings

        # --- Validate response ---
        if not isinstance(log_lines_received, list):
            logger.error(f"Invalid log content response for '{filename}': Expected list, got {type(log_lines_received)}.")
            state.update_error(f"Invalid log content format for {filename}", "logcontent")
            # Return False here as the fetch failed logically
            return False

        logger.debug(f"Received {len(log_lines_received)} log lines for '{filename}'.")

        # --- Process received lines ---
        with state.lock:
            next_start_line_calc = None
            if fetch_older and start_line_for_older_request:
                 # If we received lines *and* it was an 'older' request:
                 # If we received a full chunk, assume more older logs might exist
                 # The *next* older block starts *after* the current block
                 if len(log_lines_received) >= state.log_chunk_size:
                     next_start_line_calc = start_line_for_older_request + state.log_chunk_size
                 else:
                     # Received less than a full chunk, assume we hit the beginning
                     next_start_line_calc = None # Signal no more older logs known
            elif not fetch_older:
                 # When fetching latest via 'tail', determine if older logs *might* exist
                 # This is heuristic. If we received a full chunk, enable "Load Older".
                 # The *next* request for older should start *after* this initial chunk.
                 if len(log_lines_received) >= state.log_chunk_size:
                     # Start numbering from 1. If first chunk is 0-249, next older starts at 250.
                     next_start_line_calc = state.log_chunk_size + 1
                 elif state.log_next_fetch_start_line is None and len(self.log_lines) < state.log_chunk_size:
                     # If it's the very first fetch (no next_start set yet) and we got less than a chunk,
                     # it's likely there are no older logs either.
                     next_start_line_calc = None
                 else:
                     # Otherwise (e.g., refreshing latest when older logs already loaded),
                     # don't change the existing next_start_line pointer.
                      next_start_line_calc = state.log_next_fetch_start_line

            # Update the log lines deque and the pointer for the *next* older fetch
            state.update_log_lines(
                new_lines=log_lines_received,
                is_prepend=fetch_older, # Prepend=True means append to our deque (older logs)
                next_start_for_older=next_start_line_calc
            )
        success = True

    except requests.exceptions.HTTPError as e:
        # Handle 404 specifically - file might have rotated JUST before fetch
        if e.response is not None and e.response.status_code == 404:
            logger.warning(f"Log file '{filename}' not found (404). It might have been rotated or deleted.")
            with state.lock:
                state.log_fetch_error = f"Log file '{filename}' not found (404)."
                # If it was the *currently viewed* file that disappeared
                if state.current_log_filename == filename:
                    logger.info("Clearing log view because the current file was not found.")
                    state.log_lines.clear()
                    state.current_log_filename = None # No longer valid
                    state.log_next_fetch_start_line = None
                    # Don't automatically select a new one here, let log list fetch handle it
        else:
            # Re-raise other HTTP errors to be caught by the decorator
            logger.error(f"HTTPError fetching log content for {filename}: {e}")
            raise e # Let decorator handle generic HTTP errors
    # Other exceptions (Timeout, ConnectionError, JSONDecodeError, etc.) are handled by the decorator

    finally:
        # CRITICAL: Ensure the flag is always reset
        with state.lock:
            state.is_fetching_logcontent = False

    # Decorator handles converting exceptions to False return
    # We return success explicitly if the try block completed without error
    # We return False if we handled a specific logical failure (like 404 for current file)
    return success


# --- Scheduler Jobs ---
def fetch_stats_job():
    logger.debug("Executing scheduled stats fetch job.")
    fetch_stats_data() # Decorator handles auth and errors

def fetch_queues_job():
    logger.debug("Executing scheduled queues fetch job.")
    fetch_queues_data()

def fetch_loglist_job():
    logger.debug("Executing scheduled log list fetch job.")
    fetch_log_list()

def fetch_log_content_job(fetch_older=False):
    """Scheduled job to fetch log content (latest or older)."""
    global state
    with state.lock:
        filename = state.current_log_filename
        auto_refresh = state.log_auto_refresh_enabled
        is_fetching = state.is_fetching_logcontent

    # Conditions to fetch:
    # 1. We have a filename selected.
    # 2. EITHER it's an auto-refresh (fetch_older=False and auto_refresh=True)
    #    OR it's a forced fetch (fetch_older=True, typically user-initiated).
    # 3. We are not already fetching log content.
    should_fetch = filename and (fetch_older or auto_refresh) and not is_fetching

    if should_fetch:
        logger.debug(f"Executing scheduled log content fetch job for '{filename}', fetch_older={fetch_older}.")
        fetch_log_content(filename, fetch_older=fetch_older)
    elif not filename:
        logger.debug("Skipping log content fetch: No current log file selected.")
    elif not auto_refresh and not fetch_older:
        logger.debug("Skipping log content auto-refresh: Disabled by user.")
    elif is_fetching:
         logger.debug(f"Skipping log content fetch job for '{filename}': Already fetching.")

    # Remove one-time 'initial-log-content' tag after its first execution attempt
    # schedule.get_jobs() might include jobs that failed, check the tag directly
    jobs_to_cancel = [j for j in schedule.get_jobs() if 'initial-log-content' in j.tags]
    if jobs_to_cancel:
        for job in jobs_to_cancel:
           schedule.cancel_job(job)
           logger.debug(f"Cancelled one-time job: {job}")
    # Return None explicitly as schedule doesn't need a return value here
    return None

def run_scheduler():
    """Runs the background scheduler thread."""
    logger.info("Scheduler thread started.")
    logger.info("Performing initial data fetch...")
    # Perform initial fetches sequentially to ensure login happens first if needed
    try:
        fetch_stats_job()
        fetch_queues_job()
        fetch_loglist_job()
        # Initial log content fetch is triggered by fetch_log_list if needed
    except Exception as e:
        logger.exception("Error during initial data fetch in scheduler startup.")
    logger.info("Initial data fetch sequence complete.")

    # --- Schedule recurring jobs ---
    schedule.every(FETCH_STATS_INTERVAL_SECONDS).seconds.do(fetch_stats_job).tag('stats', 'data')
    schedule.every(FETCH_QUEUES_INTERVAL_SECONDS).seconds.do(fetch_queues_job).tag('queues', 'data')
    schedule.every(FETCH_LOGLIST_INTERVAL_SECONDS).seconds.do(fetch_loglist_job).tag('loglist', 'logs')
    # Auto-refresh log content job - runs conditionally based on state inside the job function
    schedule.every(FETCH_LOGCONTENT_INTERVAL_SECONDS).seconds.do(fetch_log_content_job, fetch_older=False).tag('logcontent-auto', 'logs')

    logger.info(f"Scheduled jobs: Stats ({FETCH_STATS_INTERVAL_SECONDS}s), Queues ({FETCH_QUEUES_INTERVAL_SECONDS}s), LogList ({FETCH_LOGLIST_INTERVAL_SECONDS}s), LogContent ({FETCH_LOGCONTENT_INTERVAL_SECONDS}s auto)")

    # --- Scheduler Loop ---
    while True:
        try:
            schedule.run_pending()
        except Exception as e:
            # Log errors in the scheduler loop itself, but keep running
            logger.error(f"Error in scheduler run_pending() loop: {e}", exc_info=True)
        time.sleep(0.5) # Check for pending jobs twice per second


# --- Flask App & Routes ---
app = Flask(__name__)
app.logger.handlers = logger.handlers # Use the configured logger
app.logger.setLevel(logger.level)
CORS(app) # Allow Cross-Origin Requests for development/flexible deployment

# --- HTML Template (Embedded) ---
# This will be a very long string. Ensure it's correctly formatted.
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BrokerDash Pro - API Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/luxon@3.0.1/build/global/luxon.min.js"></script>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><path d=%22M8.3 25L41.7 8.3L75 25L41.7 41.7L8.3 25Z%22 stroke=%22%23ff9800%22 stroke-width=%2210%22 fill=%22none%22/><path d=%22M8.3 75L41.7 58.3L75 75L41.7 91.7L8.3 75Z%22 stroke=%22%23ff5722%22 stroke-width=%2210%22 fill=%22none%22/><path d=%22M8.3 50H75%22 stroke=%22%23ffc107%22 stroke-width=%2210%22 fill=%22none%22/></svg>">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">

    {# ***** START RAW BLOCK FOR CSS ***** #}
    {% raw %}
    <style>
        /* --- CSS Variables (Theme) --- */
        :root {
            --font-family-base: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            --font-family-mono: 'Consolas', 'Monaco', 'Courier New', monospace;

            --bg-dark: #121417;
            --bg-medium: #1a1d21;
            --bg-light: #23272f;
            --bg-card: #1f2329; /* Slightly different card background */
            --bg-tooltip: rgba(15, 17, 20, 0.95);

            --text-light: #e8eaf6; /* Brighter light text */
            --text-medium: #a0a8b8; /* Adjusted medium text */
            --text-dark: #6a7386; /* Adjusted dark text */
            --text-heading: #ffffff;
            --text-inverse: #121417; /* For light backgrounds if needed */

            --border-color-strong: rgba(255, 255, 255, 0.12);
            --border-color-medium: rgba(255, 255, 255, 0.08);
            --border-color-light: rgba(255, 255, 255, 0.05);

            --accent-orange: #ff9800;
            --accent-deep-orange: #ff5722;
            --accent-yellow: #ffc107;
            --accent-green: #4caf50;
            --accent-red: #f44336;
            --accent-blue: #2196f3;
            --accent-cyan: #00bcd4;
            --accent-purple: #9c27b0;
            --accent-indigo: #5c6bc0; /* Softer indigo */
            --accent-teal: #26a69a; /* Teal */

            --status-success: var(--accent-green);
            --status-error: var(--accent-red);
            --status-warning: var(--accent-orange);
            --status-info: var(--accent-blue);
            --status-processing: var(--accent-indigo);
            --status-debug: var(--accent-cyan);
            --status-critical: #d32f2f; /* Darker red for critical */

            --gradient-red: linear-gradient(135deg, #f44336, #d32f2f);
            --gradient-orange: linear-gradient(135deg, #ffa726, #fb8c00);
            --gradient-yellow: linear-gradient(135deg, #ffeb3b, #fbc02d);
            --gradient-green: linear-gradient(135deg, #66bb6a, #388e3c);
            --gradient-blue: linear-gradient(135deg, #42a5f5, #1976d2);
            --gradient-cyan: linear-gradient(135deg, #26c6da, #0097a7);
            --gradient-purple: linear-gradient(135deg, #ab47bc, #7b1fa2);
            --gradient-indigo: linear-gradient(135deg, #7986cb, #303f9f);
            --gradient-grey: linear-gradient(135deg, #78909c, #546e7a);
            --gradient-teal: linear-gradient(135deg, #4db6ac, #00897b);

            --shadow-color: rgba(0, 0, 0, 0.3);
            --card-shadow: 0 3px 8px var(--shadow-color);
            --card-hover-shadow: 0 6px 16px var(--shadow-color);
            --border-radius-sm: 4px;
            --border-radius-md: 8px;
            --border-radius-lg: 12px;

            --transition-speed: 0.25s;
            --transition-ease: ease-in-out;
        }

        /* --- Base & Resets --- */
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        html { scroll-behavior: smooth; }
        body {
            font-family: var(--font-family-base);
            background: var(--bg-dark);
            color: var(--text-medium);
            line-height: 1.6;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
            font-size: 14px;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }
        .container { width: 100%; max-width: 1800px; margin: 0 auto; padding: 0 25px; }

        /* --- Animations --- */
        @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }
        @keyframes highlight-value { 0% { transform: scale(1); } 50% { transform: scale(1.08); color: var(--accent-yellow); } 100% { transform: scale(1); }}
        @keyframes blinkCritical { 50% { background-color: rgba(244, 67, 54, 0.3); color: #fff; } }

        /* --- Header --- */
        .app-header {
            background: rgba(26, 29, 33, 0.85); /* bg-medium with opacity */
            backdrop-filter: blur(10px);
            padding: 15px 0;
            border-bottom: 1px solid var(--border-color-medium);
            position: sticky; top: 0; z-index: 1000;
        }
        .header-content { display: flex; align-items: center; justify-content: space-between; gap: 15px; }
        .logo { display: flex; align-items: center; color: var(--accent-orange); text-decoration: none; gap: 12px; }
        .logo svg { width: 30px; height: 30px; transition: transform var(--transition-speed) var(--transition-ease); }
        .logo:hover svg { transform: rotate(-10deg); }
        .logo-text-main { font-weight: 700; font-size: 1.5em; color: var(--text-heading); letter-spacing: -0.5px; }
        .status-indicator {
            font-size: 0.9em; font-weight: 500; text-align: right; min-width: 180px;
            transition: all var(--transition-speed) var(--transition-ease);
            padding: 8px 15px; border-radius: var(--border-radius-md);
            white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
            max-width: 350px; border: 1px solid transparent;
            cursor: default; /* Indicate it's read-only */
        }
        .status-indicator.live { color: var(--status-success); background-color: rgba(76, 175, 80, 0.1); border-color: rgba(76, 175, 80, 0.4); }
        .status-indicator.error { color: var(--status-error); background-color: rgba(244, 67, 54, 0.1); border-color: rgba(244, 67, 54, 0.4); font-weight: 600; }
        .status-indicator.stale { color: var(--status-warning); background-color: rgba(255, 152, 0, 0.1); border-color: rgba(255, 152, 0, 0.4); }
        .status-indicator.fetching { color: var(--status-info); background-color: rgba(33, 150, 243, 0.1); border-color: rgba(33, 150, 243, 0.4); animation: pulse 1.5s infinite ease-in-out; }
        .status-indicator.init { color: var(--text-dark); background-color: rgba(106, 115, 134, 0.1); border-color: rgba(106, 115, 134, 0.3); }

        /* --- Main Layout --- */
        .main-layout {
            display: grid;
            grid-template-columns: repeat(12, 1fr);
            gap: 25px; padding: 35px 0; flex-grow: 1;
        }
        .section { display: contents; } /* Makes the section act like its children are direct grid items */
        .section-title {
            font-size: 1.5em; font-weight: 600; color: var(--text-heading);
            margin-bottom: 10px; /* Reduced margin */ padding-bottom: 15px;
            border-bottom: 1px solid var(--border-color-medium);
            grid-column: 1 / -1; /* Span full width */
            margin-top: 30px; /* Space between sections */
        }
        .section-title:first-of-type { margin-top: 0; } /* No top margin for the first title */

        /* --- Status Cards --- */
        .status-card {
            grid-column: span 2; /* Default: 6 cards per row */
            border-radius: var(--border-radius-lg); /* Larger radius */
            box-shadow: var(--card-shadow);
            overflow: hidden; display: flex; flex-direction: column;
            border: 1px solid var(--border-color-light);
            animation: fadeIn 0.5s ease-out forwards;
            background: var(--bg-card);
            transition: transform var(--transition-speed) var(--transition-ease), box-shadow var(--transition-speed) var(--transition-ease);
            position: relative;
            color: var(--text-heading); /* White text on gradients */
            aspect-ratio: 5 / 4; /* Slightly wider than square */
            padding: 20px 25px; /* More padding */
            background-image: var(--gradient-grey); /* Default */
        }
        .status-card:hover { transform: translateY(-5px) scale(1.02); box-shadow: var(--card-hover-shadow); }
        .card-content { z-index: 1; display: flex; flex-direction: column; justify-content: space-between; height: 100%;}
        .card-title { font-size: 0.9em; font-weight: 500; color: rgba(255,255,255,0.8); margin-bottom: 10px; text-transform: uppercase; letter-spacing: 0.8px; }
        .card-value { font-size: 2.5em; font-weight: 700; line-height: 1.1; color: #fff; display: block; margin-top: auto; text-shadow: 0 2px 4px rgba(0,0,0,0.4); transition: color 0.3s ease, transform 0.3s ease; }
        .card-value.small { font-size: 1.9em; }
        .value-changed .card-value { animation: highlight-value 0.4s ease-out; }
        .card-icon { position: absolute; bottom: 15px; right: 20px; font-size: 3.5em; opacity: 0.15; user-select: none; line-height: 1; color: #fff;}

        /* Card Backgrounds */
        .card-bg-pending { background-image: var(--gradient-orange); }
        .card-bg-processing { background-image: var(--gradient-blue); }
        .card-bg-failed { background-image: var(--gradient-red); }
        .card-bg-processed { background-image: var(--gradient-green); }
        .card-bg-total-msgs { background-image: var(--gradient-cyan); }
        .card-bg-total-queues { background-image: var(--gradient-purple); }
        .card-bg-total-reqs { background-image: var(--gradient-indigo); }
        .card-bg-uptime { background-image: var(--gradient-grey); }
        .card-bg-cpu { background-image: var(--gradient-indigo); } /* Reuse */
        .card-bg-mem { background-image: var(--gradient-teal); }
        .card-bg-error-rate { background-image: var(--gradient-red); } /* Reuse */
        .card-bg-files-threads { background-image: var(--gradient-grey); } /* Reuse */

        /* API Error Card */
        .last-error-card {
            grid-column: 1 / -1; /* Span full width */
            background: linear-gradient(135deg, rgba(244, 67, 54, 0.2), rgba(211, 47, 47, 0.3));
            border: 1px solid rgba(244, 67, 54, 0.4);
            color: #ffcdd2; /* Light red text */
            backdrop-filter: blur(4px);
            aspect-ratio: auto; /* Allow height to adjust */
            padding: 20px 30px;
        }
        .last-error-card .card-title { color: #ff8a80; font-weight: 600;}
        .last-error-card .card-value { font-size: 1em; line-height: 1.5; color: #ffcdd2; font-weight: 400; white-space: pre-wrap; word-break: break-word; text-shadow: none; }
        .error-timestamp { font-size: 0.8em; color: var(--text-dark); margin-top: 10px; display: block; }

        /* --- Chart Cards --- */
        .chart-card {
            grid-column: span 4; /* Default: 3 charts per row */
            background: var(--bg-card); border-radius: var(--border-radius-lg); padding: 25px 30px 30px 30px;
            box-shadow: var(--card-shadow); border: 1px solid var(--border-color-light);
            animation: fadeIn 0.6s ease-out forwards; display: flex; flex-direction: column;
        }
        .chart-title { font-size: 1.05em; font-weight: 500; color: var(--text-light); margin-bottom: 25px; text-align: center; }
        .chart-container { min-height: 320px; height: 100%; position: relative; flex-grow: 1; }
        .chart-container canvas { display: block; width: 100%; height: 100%; }

        /* --- Info/Table Cards --- */
        .info-card {
             grid-column: span 6; /* Default: 2 info cards per row */
             background: var(--bg-card); border-radius: var(--border-radius-lg); padding: 30px;
             box-shadow: var(--card-shadow); border: 1px solid var(--border-color-light);
             animation: fadeIn 0.7s ease-out forwards; display: flex; flex-direction: column;
             font-size: 0.95em;
        }
        .info-title { font-size: 1.2em; font-weight: 600; color: var(--text-heading); margin-bottom: 20px; }
        .info-table { width: 100%; border-collapse: collapse; }
        .info-table th, .info-table td { padding: 12px 8px; text-align: left; border-bottom: 1px solid var(--border-color-medium); vertical-align: top; }
        .info-table th { font-weight: 500; color: var(--text-medium); white-space: nowrap; padding-right: 25px; width: 35%; }
        .info-table td { color: var(--text-light); word-break: break-word; }
        .info-table tr:last-child th, .info-table tr:last-child td { border-bottom: none; }
        .info-table code { background-color: var(--bg-medium); padding: 3px 7px; border-radius: var(--border-radius-sm); font-size: 0.95em; font-family: var(--font-family-mono); color: var(--accent-cyan);}
        .no-data { text-align: center; color: var(--text-dark); padding: 20px; font-style: italic; }

        /* Disk Usage Bar */
        .disk-usage-bar-container { display: flex; align-items: center; gap: 10px; }
        .disk-usage-text { white-space: nowrap; font-size: 0.95em; color: var(--text-light); }
        .disk-usage-bar { flex-grow: 1; background-color: rgba(0,0,0,0.3); height: 12px; border-radius: 6px; overflow: hidden; border: 1px solid var(--border-color-light);}
        .disk-usage-fill { height: 100%; background-image: var(--gradient-green); transition: width 0.4s ease; border-radius: 5px; }
        .disk-usage-fill.warn { background-image: var(--gradient-orange); }
        .disk-usage-fill.crit { background-image: var(--gradient-red); }

        /* Queues Table Specific */
        .queues-table-wrapper { max-height: 380px; overflow-y: auto; margin: -10px; padding: 10px; /* Offset padding */ scrollbar-width: thin; scrollbar-color: var(--text-dark) var(--bg-light); }
        .queues-table-wrapper::-webkit-scrollbar { width: 8px; }
        .queues-table-wrapper::-webkit-scrollbar-track { background: var(--bg-light); border-radius: 4px; }
        .queues-table-wrapper::-webkit-scrollbar-thumb { background-color: var(--text-dark); border-radius: 4px; border: 2px solid var(--bg-light); }
        #queue-count { font-weight: 600; color: var(--accent-purple); }

        /* --- Log Viewer --- */
        .log-viewer-card {
            grid-column: 1 / -1; background: var(--bg-card); border-radius: var(--border-radius-lg);
            padding: 25px 30px; box-shadow: var(--card-shadow); border: 1px solid var(--border-color-light);
            display: flex; flex-direction: column; margin-top: 10px;
        }
        .log-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; flex-wrap: wrap; gap: 20px;}
        .log-title-section { display: flex; align-items: baseline; gap: 15px; }
        .log-title { font-size: 1.2em; font-weight: 600; color: var(--text-heading); }
        .log-filename { font-family: var(--font-family-mono); font-size: 1em; color: var(--text-light); background-color: var(--bg-medium); padding: 5px 12px; border-radius: var(--border-radius-sm); border: 1px solid var(--border-color-light); }
        .log-filename.na { color: var(--text-dark); font-style: italic; }

        /* Log Controls */
        .log-controls { display: flex; align-items: center; gap: 15px; flex-wrap: wrap; }
        .log-controls .control-group { display: flex; align-items: center; gap: 10px;}
        .log-controls label { font-size: 0.9em; color: var(--text-medium); cursor: pointer; }
        .log-controls input[type="checkbox"] { cursor: pointer; accent-color: var(--accent-orange); width: 16px; height: 16px; transform: translateY(2px); }
        .log-controls input[type="text"], .log-controls select {
            background-color: var(--bg-light); border: 1px solid var(--border-color-medium);
            color: var(--text-light); padding: 8px 12px; border-radius: var(--border-radius-sm);
            font-size: 0.9em; transition: border-color var(--transition-speed);
        }
        .log-controls input[type="text"]:focus, .log-controls select:focus { outline: none; border-color: var(--accent-blue); box-shadow: 0 0 0 2px rgba(33, 150, 243, 0.3); }
        .log-controls input[type="text"] { font-family: var(--font-family-mono); width: 180px; }
        .log-controls select { cursor: pointer; appearance: none; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='%23a0a8b8'%3E%3Cpath fill-rule='evenodd' d='M8 11.5a.5.5 0 0 1-.354-.146l-4-4a.5.5 0 0 1 .708-.708L8 10.293l3.646-3.647a.5.5 0 0 1 .708.708l-4 4A.5.5 0 0 1 8 11.5z'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 10px center; background-size: 16px; padding-right: 30px; }
        .log-controls button {
            background: var(--bg-light); color: var(--text-medium); border: 1px solid var(--border-color-medium);
            padding: 8px 18px; border-radius: var(--border-radius-sm); cursor: pointer; font-size: 0.9em; font-weight: 500;
            transition: all var(--transition-speed) var(--transition-ease);
        }
        .log-controls button:hover:not(:disabled) { background-color: var(--bg-medium); color: var(--text-light); border-color: var(--text-medium); }
        .log-controls button:active:not(:disabled) { transform: scale(0.97); }
        .log-controls button:disabled { opacity: 0.5; cursor: not-allowed; background-color: var(--bg-light); border-color: var(--border-color-light); color: var(--text-dark);}

        /* Log Content Area */
        .log-content-wrapper {
            background-color: #15171a; /* Slightly darker than card */
            border: 1px solid var(--border-color-strong); border-radius: var(--border-radius-md);
            flex-grow: 1; overflow: auto; max-height: 650px; /* Increased height */
            font-family: var(--font-family-mono); font-size: 0.88em; line-height: 1.7;
            margin-top: 10px; /* Space below controls */
            position: relative; /* For absolute positioning of status */
            scrollbar-width: thin; scrollbar-color: var(--text-dark) var(--bg-light);
        }
        .log-content-wrapper::-webkit-scrollbar { width: 10px; }
        .log-content-wrapper::-webkit-scrollbar-track { background: var(--bg-light); border-radius: 5px; }
        .log-content-wrapper::-webkit-scrollbar-thumb { background-color: var(--text-dark); border-radius: 5px; border: 2px solid var(--bg-light); }
        .log-line { display: flex; padding: 2px 15px; border-bottom: 1px solid var(--border-color-light); white-space: pre-wrap; word-break: break-word; transition: background-color 0.15s ease; }
        .log-line:hover { background-color: rgba(255, 255, 255, 0.03); }
        .log-line.hidden { display: none; } /* For filtering */
        .log-line-timestamp { color: var(--text-dark); margin-right: 15px; user-select: none; min-width: 75px; padding-top: 1px;}
        .log-line-level { font-weight: 600; margin-right: 12px; min-width: 80px; display: inline-block; text-transform: uppercase; text-align: right; }
        .log-line-level.critical { color: var(--status-critical); animation: blinkCritical 1.2s infinite ease-in-out; }
        .log-line-level.error { color: var(--status-error); }
        .log-line-level.warning { color: var(--status-warning); }
        .log-line-level.info { color: var(--status-info); }
        .log-line-level.debug { color: var(--status-debug); }
        .log-line-message { flex-grow: 1; color: var(--text-light); }
        .log-highlight { background-color: rgba(255, 193, 7, 0.25); border-radius: 2px; box-shadow: 0 0 0 1px rgba(255, 193, 7, 0.4); } /* Search highlight */
        .log-status-overlay { /* To show messages like 'Loading...' or 'No logs' */
            position: absolute; top: 0; left: 0; right: 0; bottom: 0;
            display: flex; align-items: center; justify-content: center;
            background-color: rgba(21, 23, 26, 0.8); /* Semi-transparent overlay */
            color: var(--text-medium); font-size: 1.1em; font-style: italic;
            z-index: 10; pointer-events: none; /* Allow clicking through if needed */
            opacity: 0; transition: opacity var(--transition-speed) ease;
        }
         .log-status-overlay.visible { opacity: 1; pointer-events: auto; }

        /* Log Status Text (Below Controls) */
        .log-status-display { font-size: 0.85em; color: var(--text-dark); text-align: right; min-height: 1.5em; }

        /* --- Footer --- */
        .app-footer {
            text-align: center; padding: 35px 0; margin-top: auto;
            font-size: 0.9em; color: var(--text-dark);
            border-top: 1px solid var(--border-color-medium); background: var(--bg-medium);
        }
        .footer-status { font-weight: 500; display: block; margin-top: 10px; transition: color 0.3s ease;}
        .footer-status .status-icon { margin-right: 5px; }
        .footer-status.error { color: var(--status-error); font-weight: 600; }
        .footer-status.success { color: var(--text-medium); }
        .footer-status.stale { color: var(--status-warning); }

        /* --- Responsive Design --- */
        @media (max-width: 1600px) {
            .status-card { grid-column: span 3; /* 4 cards row */ aspect-ratio: 4 / 3; }
            .chart-card { grid-column: span 6; /* 2 charts row */ }
            .info-card { grid-column: span 6; }
        }
        @media (max-width: 1200px) {
            .status-card { grid-column: span 4; /* 3 cards row */ }
            .chart-card { grid-column: span 6; }
            .info-card { grid-column: span 6; }
             .log-controls { justify-content: flex-start; }
        }
        @media (max-width: 992px) {
            .container { padding: 0 15px; }
            .main-layout { gap: 20px; padding: 25px 0; }
            .status-card { grid-column: span 6; /* 2 cards row */ aspect-ratio: 16 / 9; }
            .chart-card { grid-column: span 12; /* 1 chart row */ }
            .info-card { grid-column: span 12; }
            .section-title { font-size: 1.3em; }
            .log-header { flex-direction: column; align-items: stretch; gap: 15px;}
            .log-title-section { justify-content: space-between; }
            .log-controls { gap: 10px; }
        }
         @media (max-width: 768px) {
             body { font-size: 13px; }
             .app-header { padding: 12px 0; }
             .header-content { flex-direction: column; align-items: center; gap: 12px;}
             .status-indicator { max-width: 90%; }
             .status-card { grid-column: span 6; aspect-ratio: auto; min-height: 130px;}
             .card-value { font-size: 2.1em; } .card-value.small { font-size: 1.7em; }
             .log-controls .control-group { width: 100%; justify-content: space-between; }
             .log-controls input[type="text"] { width: calc(100% - 110px); } /* Adjust width */
             .log-controls select { width: 100px; }
             .log-controls button { flex-grow: 1; text-align: center; }
             .log-content-wrapper { max-height: 500px; }
             .info-table th { width: auto; } /* Let table layout decide */
             .info-table th, .info-table td { padding: 10px 5px; }
         }
        @media (max-width: 576px) {
            .status-card { grid-column: span 12; } /* 1 card row */
            .card-value { font-size: 2.3em; }
            .chart-container { min-height: 280px; }
            .log-controls { flex-direction: column; align-items: stretch; }
             .log-controls .control-group { flex-direction: column; align-items: stretch; gap: 8px; }
             .log-controls input[type="text"], .log-controls select, .log-controls button { width: 100%; }
        }
    </style>
    {% endraw %}
    {# ***** END RAW BLOCK FOR CSS ***** #}
</head>
<body>
    <header class="app-header">
        <div class="container">
            <div class="header-content">
                <a href="/" class="logo" title="BrokerDash Pro Home">
                     <svg viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M8.3 25L41.7 8.3L75 25L41.7 41.7L8.3 25Z" stroke="currentColor" stroke-width="10"/><path d="M8.3 75L41.7 58.3L75 75L41.7 91.7L8.3 75Z" stroke="var(--accent-deep-orange)" stroke-width="10"/><path d="M8.3 50H75" stroke="var(--accent-yellow)" stroke-width="10"/></svg>
                    <span class="logo-text-main">BrokerDash Pro</span>
                </a>
                <div id="status-indicator" class="status-indicator init" title="Status of connection to API">Initializing...</div>
            </div>
        </div>
    </header>

    <div class="container">
        <main class="main-layout">
            <!-- API Error Display -->
            <div class="status-card last-error-card" id="card-last-error" style="display: none;">
                 <div class="card-content">
                     <div class="card-title">🚨 API Communication Error</div>
                     <div class="card-value small" id="last-error-message">--</div>
                     <div class="error-timestamp" id="last-error-timestamp"></div>
                 </div>
            </div>

             <!-- Broker Status Section -->
             <div class="section">
                 <h2 class="section-title">Broker Message Status</h2>
                 <div class="status-card card-bg-pending"><div class="card-content"><div class="card-title">Pending</div><div class="card-value" id="value-pending-msgs">--</div></div><div class="card-icon">📥</div></div>
                 <div class="status-card card-bg-processing"><div class="card-content"><div class="card-title">Processing</div><div class="card-value" id="value-processing-msgs">--</div></div><div class="card-icon">⚙️</div></div>
                 <div class="status-card card-bg-failed"><div class="card-content"><div class="card-title">Failed</div><div class="card-value" id="value-failed-msgs">--</div></div><div class="card-icon">❌</div></div>
                 <div class="status-card card-bg-processed"><div class="card-content"><div class="card-title">Processed</div><div class="card-value" id="value-processed-msgs">--</div></div><div class="card-icon">✅</div></div>
                 <div class="status-card card-bg-total-msgs"><div class="card-content"><div class="card-title">Total Msgs</div><div class="card-value" id="value-total-msgs">--</div></div><div class="card-icon">✉️</div></div>
                 <div class="status-card card-bg-total-queues"><div class="card-content"><div class="card-title">Active Queues</div><div class="card-value" id="value-total-queues">--</div></div><div class="card-icon">📁</div></div>
            </div>

            <!-- API & System Performance Section -->
             <div class="section">
                 <h2 class="section-title">API Performance & System Health</h2>
                 <div class="status-card card-bg-total-reqs"><div class="card-content"><div class="card-title">Total Requests</div><div class="card-value" id="value-total-requests">--</div></div><div class="card-icon">📈</div></div>
                 <div class="status-card card-bg-error-rate"><div class="card-content"><div class="card-title">HTTP Err Rate % (Interval)</div><div class="card-value small" id="value-http-error-rate">--</div></div><div class="card-icon">🚦</div></div>
                 <div class="status-card card-bg-cpu"><div class="card-content"><div class="card-title">API Process CPU %</div><div class="card-value small" id="value-process-cpu">--</div></div><div class="card-icon">⚙️</div></div>
                 <div class="status-card card-bg-mem"><div class="card-content"><div class="card-title">API Process Mem</div><div class="card-value small" id="value-process-mem">--</div></div><div class="card-icon">🧠</div></div>
                 <div class="status-card card-bg-cpu"><div class="card-content"><div class="card-title">System CPU %</div><div class="card-value small" id="value-system-cpu">--</div></div><div class="card-icon">💻</div></div>
                 <div class="status-card card-bg-mem"><div class="card-content"><div class="card-title">System Mem %</div><div class="card-value small" id="value-system-mem">--</div></div><div class="card-icon">💾</div></div>
                 <div class="status-card card-bg-uptime"><div class="card-content"><div class="card-title">API Uptime</div><div class="card-value small" id="value-uptime">--</div></div><div class="card-icon">⏳</div></div>
                 <div class="status-card card-bg-files-threads"><div class="card-content"><div class="card-title">Open Files / Threads</div><div class="card-value small" id="value-files-threads">-- / --</div></div><div class="card-icon">📄</div></div>
            </div>

            <!-- Historical Trends Section -->
            <div class="section">
                 <h2 class="section-title">Historical Trends</h2>
                 <div class="chart-card">
                     <div class="chart-title">Message Throughput & Failures (Events/sec)</div>
                     <div class="chart-container"><canvas id="ratesChart"></canvas></div>
                 </div>
                 <div class="chart-card">
                     <div class="chart-title">Message Status Queue Size</div>
                     <div class="chart-container"><canvas id="messageStatusChart"></canvas></div>
                 </div>
                 <div class="chart-card">
                     <div class="chart-title">Resource Utilization (%)</div>
                     <div class="chart-container"><canvas id="performanceChart"></canvas></div>
                 </div>
            </div>

            <!-- Request Analysis Section -->
            <div class="section">
                 <h2 class="section-title">Request Analysis</h2>
                 <div class="chart-card">
                     <div class="chart-title">HTTP Status Code Distribution (Total)</div>
                     <div class="chart-container"><canvas id="requestsByStatusChart"></canvas></div>
                 </div>
                 <div class="chart-card">
                     <div class="chart-title">Top 15 API Routes by Request Count (Total)</div>
                     <div class="chart-container"><canvas id="requestsByRouteChart"></canvas></div>
                 </div>
                  <div class="chart-card">
                     <div class="chart-title">HTTP Error Rate (% over time)</div>
                     <div class="chart-container"><canvas id="httpErrorRateChart"></canvas></div>
                 </div>
            </div>

            <!-- System & Config Details Section -->
             <div class="section">
                 <h2 class="section-title">System & Configuration Details</h2>
                 <div class="info-card" id="system-info-card">
                     <div class="info-title">💻 System Information</div>
                     <table class="info-table" id="system-info-table"><tbody><tr><td colspan="2" class="no-data">Loading...</td></tr></tbody></table>
                 </div>
                 <div class="info-card" id="broker-info-card">
                     <div class="info-title">🛠️ Broker Configuration</div>
                     <table class="info-table" id="broker-info-table"><tbody><tr><td colspan="2" class="no-data">Loading...</td></tr></tbody></table>
                 </div>
                 <div class="info-card" id="queues-info-card">
                     <div class="info-title">📁 Queue Details (<span id="queue-count">0</span>)</div>
                     <div class="queues-table-wrapper">
                        <table class="info-table" id="queues-info-table">
                           <thead><tr><th>Name</th><th>Total Msgs</th><th>Created</th></tr></thead>
                           <tbody><tr><td colspan="3" class="no-data">Loading...</td></tr></tbody>
                        </table>
                     </div>
                 </div>
                 <div class="info-card" id="disk-info-card">
                      <div class="info-title">💾 Disk Usage</div>
                      <table class="info-table" id="disk-info-table">
                          <thead><tr><th>Mountpoint</th><th>Usage</th><th>Free Space</th></tr></thead>
                          <tbody><tr><td colspan="3" class="no-data">Loading...</td></tr></tbody>
                      </table>
                 </div>
            </div>

            <!-- Log Viewer Section -->
             <div class="section">
                 <h2 class="section-title">Log Viewer</h2>
                 <div class="log-viewer-card">
                      <div class="log-header">
                         <div class="log-title-section">
                             <span class="log-title">Current File:</span>
                             <span class="log-filename na" id="log-filename-display">N/A</span>
                         </div>
                         <div class="log-controls">
                            <div class="control-group">
                               <input type="text" id="log-search-input" placeholder="Search logs..." aria-label="Search logs">
                               <label for="log-filter-level">Level:</label>
                               <select id="log-filter-level" aria-label="Filter logs by level">
                                   <option value="">All</option>
                                   <option value="critical">Critical</option>
                                   <option value="error">Error</option>
                                   <option value="warning">Warning</option>
                                   <option value="info">Info</option>
                                   <option value="debug">Debug</option>
                               </select>
                           </div>
                            <div class="control-group">
                                <label for="log-auto-refresh-toggle" title="Toggle automatic log refreshing every {{ FETCH_LOGCONTENT_INTERVAL_SECONDS }} seconds">Auto-Refresh:</label>
                                <input type="checkbox" id="log-auto-refresh-toggle" checked>
                           </div>
                           <div class="control-group">
                                <button id="load-older-logs-btn" title="Load older log entries" disabled>Load Older</button>
                                <button id="refresh-logs-btn" title="Fetch latest log entries now">Refresh Now</button>
                           </div>
                         </div>
                     </div>
                     <div class="log-status-display" id="log-status-text"></div>
                      <div class="log-content-wrapper" id="log-content-area">
                          <div class="log-line no-data" id="log-initial-message">(Initializing log viewer...)</div>
                          <div class="log-status-overlay" id="log-status-overlay"></div>
                     </div>
                 </div>
            </div>

        </main>
    </div>

    <footer class="app-footer">
        BrokerDash Pro - Real-time API Metrics Dashboard
        <div class="footer-status success" id="footer-backend-status"><span class="status-icon"></span>Initializing connection...</div>
    </footer>

    {# ***** START RAW BLOCK FOR JS ***** #}
    {% raw %}
    <script>
        // --- Injected Config ---
        const CONFIG = {
            API_DASHBOARD_DATA_URL: '/api/dashboard_data',
            API_LOG_DATA_URL: '/api/log_data',
            API_FETCH_OLDER_LOGS_URL: '/api/fetch_older_logs',
            API_TOGGLE_LOG_REFRESH_URL: '/api/toggle_log_refresh',
            POLLING_INTERVAL_MS: {{ FETCH_STATS_INTERVAL_SECONDS * 1000 }},
            LOG_REFRESH_INTERVAL_MS: {{ FETCH_LOGCONTENT_INTERVAL_SECONDS * 1000 }},
            MAX_CHART_HISTORY: {{ MAX_CHART_HISTORY }},
            LOG_CHUNK_SIZE: {{ LOG_CHUNK_SIZE }},
            FETCH_STATS_INTERVAL_SECONDS: {{ FETCH_STATS_INTERVAL_SECONDS }} // For chart label
        };

        // --- Global JS State ---
        const DateTime = luxon.DateTime;
        let chartInstances = {};
        let fetchDataIntervalId = null;
        let fetchLogIntervalId = null;
        let lastKnownApiError = null;
        let lastSuccessfulDataFetch = null;
        let logAutoRefreshEnabled = true; // Default, synced with backend
        let currentLogFilename = null; // Keep track locally
        let canLoadOlderLogs = false;
        let isFetchingLogs = false; // Prevent concurrent log fetches
        let logSearchTerm = '';
        let logFilterLevel = '';
        let logSearchDebounceTimeout = null;
        let initialLoadComplete = false;

        // --- DOM Element Cache ---
        let dom = {}; // Initialized in cacheDOMElements

        // --- Initialization ---
        document.addEventListener('DOMContentLoaded', () => {
            console.info("BrokerDash Pro: DOM Loaded. Initializing...");
            cacheDOMElements();
            initializeCharts();
            setupEventListeners();
            clearUI(); // Set initial state
            updateStatusIndicator('init', 'Initializing...'); // Initial status

            // Start fetching data
            fetchDashboardData(); // Initial high-level data fetch
            // Log data fetch is triggered by fetchDashboardData based on state

            // Setup polling intervals
            if (fetchDataIntervalId) clearInterval(fetchDataIntervalId);
            fetchDataIntervalId = setInterval(fetchDashboardData, CONFIG.POLLING_INTERVAL_MS);
            startLogAutoRefreshTimer(); // Start conditional log auto-refresh timer

            console.info(`Polling dashboard data every ${CONFIG.POLLING_INTERVAL_MS / 1000}s.`);
            console.info(`Log auto-refresh interval: ${CONFIG.LOG_REFRESH_INTERVAL_MS / 1000}s (will enable/disable based on state).`);
        });

        function cacheDOMElements() {
            dom = {
                statusIndicator: document.getElementById('status-indicator'),
                footerStatus: document.getElementById('footer-backend-status'),
                lastErrorCard: document.getElementById('card-last-error'),
                lastErrorMessage: document.getElementById('last-error-message'),
                lastErrorTimestamp: document.getElementById('last-error-timestamp'),
                // Cards
                pendingMsgs: document.getElementById('value-pending-msgs'),
                processingMsgs: document.getElementById('value-processing-msgs'),
                failedMsgs: document.getElementById('value-failed-msgs'),
                processedMsgs: document.getElementById('value-processed-msgs'),
                totalMsgs: document.getElementById('value-total-msgs'),
                totalQueues: document.getElementById('value-total-queues'),
                totalRequests: document.getElementById('value-total-requests'),
                httpErrorRate: document.getElementById('value-http-error-rate'),
                uptime: document.getElementById('value-uptime'),
                processCpu: document.getElementById('value-process-cpu'),
                processMem: document.getElementById('value-process-mem'),
                systemCpu: document.getElementById('value-system-cpu'),
                systemMem: document.getElementById('value-system-mem'),
                filesThreads: document.getElementById('value-files-threads'),
                // Tables & Info
                systemInfoTableBody: document.querySelector('#system-info-table tbody'),
                brokerInfoTableBody: document.querySelector('#broker-info-table tbody'),
                queuesInfoTableBody: document.querySelector('#queues-info-table tbody'),
                diskInfoTableBody: document.querySelector('#disk-info-table tbody'),
                queueCountSpan: document.getElementById('queue-count'),
                // Charts (Canvas elements)
                ratesChartCanvas: document.getElementById('ratesChart'),
                messageStatusChartCanvas: document.getElementById('messageStatusChart'),
                performanceChartCanvas: document.getElementById('performanceChart'),
                requestsByRouteChartCanvas: document.getElementById('requestsByRouteChart'),
                requestsByStatusChartCanvas: document.getElementById('requestsByStatusChart'),
                httpErrorRateChartCanvas: document.getElementById('httpErrorRateChart'),
                // Log Viewer
                logFilenameDisplay: document.getElementById('log-filename-display'),
                logContentArea: document.getElementById('log-content-area'),
                logStatusText: document.getElementById('log-status-text'),
                logStatusOverlay: document.getElementById('log-status-overlay'),
                logInitialMessage: document.getElementById('log-initial-message'),
                loadOlderLogsBtn: document.getElementById('load-older-logs-btn'),
                refreshLogsBtn: document.getElementById('refresh-logs-btn'),
                logAutoRefreshToggle: document.getElementById('log-auto-refresh-toggle'),
                logSearchInput: document.getElementById('log-search-input'),
                logFilterLevel: document.getElementById('log-filter-level'),
            };
            // Get contexts for charts
             dom.ratesChartCtx = dom.ratesChartCanvas?.getContext('2d');
             dom.messageStatusChartCtx = dom.messageStatusChartCanvas?.getContext('2d');
             dom.performanceChartCtx = dom.performanceChartCanvas?.getContext('2d');
             dom.requestsByRouteChartCtx = dom.requestsByRouteChartCanvas?.getContext('2d');
             dom.requestsByStatusChartCtx = dom.requestsByStatusChartCanvas?.getContext('2d');
             dom.httpErrorRateChartCtx = dom.httpErrorRateChartCanvas?.getContext('2d');
             console.debug("DOM elements cached.");
        }

        function startLogAutoRefreshTimer() {
             if (fetchLogIntervalId) clearInterval(fetchLogIntervalId); // Clear existing timer
             if (logAutoRefreshEnabled && currentLogFilename) { // Only run if enabled AND a file is selected
                 fetchLogIntervalId = setInterval(() => fetchLogData(false), CONFIG.LOG_REFRESH_INTERVAL_MS);
                 console.info("Log auto-refresh timer started.");
             } else {
                 console.info(`Log auto-refresh timer ${currentLogFilename ? 'disabled' : 'inactive (no log file selected)'}.`);
             }
        }

        // --- Formatters & Helpers ---
        function safeGet(obj, path, defaultValue = null) { if (!obj || typeof path !== 'string') return defaultValue; try { return path.split('.').reduce((acc, key) => (acc && acc[key] !== undefined && acc[key] !== null) ? acc[key] : defaultValue, obj); } catch (e) { return defaultValue; } }
        function formatNumber(num) { const n = parseFloat(num); return (n === null || n === undefined || isNaN(n)) ? '--' : n.toLocaleString(undefined, { maximumFractionDigits: 0 }); }
        function formatDecimal(num, digits = 1) { const n = parseFloat(num); return (n === null || n === undefined || isNaN(n)) ? '--' : n.toLocaleString(undefined, { minimumFractionDigits: digits, maximumFractionDigits: digits }); }
        function formatPercentage(num) { const n = parseFloat(num); return (n === null || n === undefined || isNaN(n)) ? '--' : formatDecimal(n, 1) + '%'; }
        function formatMemory(num, unit = 'MB') { return (num === null || num === undefined || isNaN(parseFloat(num))) ? '--' : `${formatDecimal(num, 1)} ${unit}`; }
        function formatBytes(num) { const n = parseInt(num, 10); if (n === null || n === undefined || isNaN(n)) return '--'; const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']; if (n === 0) return '0 B'; const i = parseInt(Math.floor(Math.log(n) / Math.log(1024)), 10); if (i < 0 || i >= sizes.length) return `${n} B`; /* Handle very small or large */ if (i === 0) return `${n} ${sizes[i]}`; return `${formatDecimal(n / (1024 ** i), 1)} ${sizes[i]}`; }
        function formatDateTime(isoString, format = DateTime.DATETIME_SHORT_WITH_SECONDS) { if (!isoString) return '--'; try { const dt = DateTime.fromISO(isoString); return dt.isValid ? dt.toLocaleString(format) : isoString; } catch (e) { return isoString; } }
        function formatRelativeTime(isoString) { if (!isoString) return '--'; try { const dt = DateTime.fromISO(isoString); return dt.isValid ? dt.toRelative() : 'invalid date'; } catch (e) { return 'invalid date'; } }
        function formatUptime(uptimeStr) { return uptimeStr || '--'; } // Assuming backend sends pre-formatted string
        function formatLoadAvg(loadTuple) { if (!Array.isArray(loadTuple) || loadTuple.length < 3) return '--'; return loadTuple.map(n => (n === null || n === undefined || isNaN(parseFloat(n))) ? '?' : parseFloat(n).toFixed(2)).join(', '); }
        function formatFilesThreads(files, threads) { const f = formatNumber(files); const t = formatNumber(threads); return `${f} / ${t}`; }
        function generateColors(count) { const base = ['#64b5f6','#81c784','#ffb74d','#e57373','#ba68c8','#4dd0e1','#fff176','#7986cb','#a1887f','#90a4ae','#ff8a65','#4db6ac','#9575cd','#f06292','#69f0ae']; return Array.from({ length: count }, (_, i) => base[i % base.length]); }
        function getHttpStatusColor(code) { code = parseInt(code); if (code >= 500) return 'var(--status-error)'; if (code >= 400) return 'var(--status-warning)'; if (code >= 300) return 'var(--status-info)'; if (code >= 200) return 'var(--status-success)'; return 'var(--text-dark)'; }
        function escapeHtml(unsafe) { return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;"); }

        // --- UI Update Functions ---
        function updateCardValue(element, newValue, formatter = formatNumber) {
            if (!element) return;
            try {
                const formattedValue = formatter(newValue);
                if (element.textContent !== formattedValue) {
                    element.textContent = formattedValue;
                    const card = element.closest('.status-card');
                    if (card && card.classList.contains('value-changed')) {
                       // If animation is already running, reset it quickly to restart
                       card.classList.remove('value-changed');
                       void card.offsetWidth; // Trigger reflow
                    }
                    if (card) card.classList.add('value-changed');
                    setTimeout(() => card?.classList.remove('value-changed'), 450);
                }
            } catch (e) {
                console.error(`Error formatting/updating card value: ${e}`, element, newValue);
                element.textContent = 'ERR';
            }
        }

        function updateChartData(chartInstance, newLabels = [], newDatasetsData = []) {
             if (!chartInstance?.config?._config) { console.warn("Attempted to update non-existent chart"); return; }
             chartInstance.data.labels = newLabels;
             chartInstance.data.datasets.forEach((dataset, index) => {
                 const dataForDataset = (Array.isArray(newDatasetsData) && index < newDatasetsData.length && Array.isArray(newDatasetsData[index])) ? newDatasetsData[index] : [];
                 dataset.data = dataForDataset;

                 // Dynamically update colors for categorical charts if needed
                  if ((chartInstance.config.type === 'doughnut' || chartInstance.config.type === 'pie' || chartInstance.config.type === 'bar') && dataset.backgroundColor) {
                     if (chartInstance.canvas.id === 'requestsByStatusChart') {
                         dataset.backgroundColor = newLabels.map(label => getHttpStatusColor(label));
                         dataset.hoverBackgroundColor = dataset.backgroundColor; // Keep hover same
                     } else if (chartInstance.canvas.id === 'requestsByRouteChart') {
                         // Consistent color for route bars
                          dataset.backgroundColor = 'var(--accent-indigo)';
                          dataset.hoverBackgroundColor = 'var(--accent-blue)';
                     } else {
                         dataset.backgroundColor = generateColors(dataForDataset.length);
                         dataset.hoverBackgroundColor = dataset.backgroundColor;
                     }
                 }
             });
             chartInstance.update('none'); // 'none' for no animation on update
        }

        function clearUI() {
             console.log("Clearing UI to initial state.");
             Object.values(dom).forEach(el => {
                if (!el) return;
                if (el.classList?.contains('card-value')) el.textContent = '--';
                if (el.tagName === 'TBODY') el.innerHTML = `<tr><td colspan="${el.closest('table')?.querySelector('thead tr')?.children.length || 2}" class="no-data">(Waiting for data...)</td></tr>`;
                if (el.id === 'queue-count') el.textContent = '0';
             });
             if (dom.logFilenameDisplay) { dom.logFilenameDisplay.textContent = 'N/A'; dom.logFilenameDisplay.classList.add('na'); }
             if (dom.logContentArea && dom.logInitialMessage) { dom.logContentArea.innerHTML = ''; dom.logContentArea.appendChild(dom.logInitialMessage); dom.logInitialMessage.textContent = "(Waiting for data...)"; dom.logInitialMessage.style.display = 'block'; }
             if (dom.logStatusText) dom.logStatusText.textContent = '';
             if (dom.logStatusOverlay) { dom.logStatusOverlay.textContent = ''; dom.logStatusOverlay.classList.remove('visible'); }
             if (dom.loadOlderLogsBtn) dom.loadOlderLogsBtn.disabled = true;
             if (dom.refreshLogsBtn) dom.refreshLogsBtn.disabled = true; // Disable initially
             if (dom.lastErrorCard) dom.lastErrorCard.style.display = 'none';
             Object.values(chartInstances).forEach(chart => { if(chart) updateChartData(chart); });
             lastKnownApiError = null; // Reset error state
             lastSuccessfulDataFetch = null; // Reset fetch time
             currentLogFilename = null;
             canLoadOlderLogs = false;
        }

        function setLogOverlay(message, isVisible) {
            if (!dom.logStatusOverlay) return;
            dom.logStatusOverlay.textContent = message;
            if (isVisible) {
                dom.logStatusOverlay.classList.add('visible');
            } else {
                dom.logStatusOverlay.classList.remove('visible');
            }
        }

        // --- Chart Initialization ---
        function initializeCharts() {
             console.log("Initializing charts...");
             if (!dom.ratesChartCtx || !dom.messageStatusChartCtx || !dom.performanceChartCtx || !dom.requestsByRouteChartCtx || !dom.requestsByStatusChartCtx || !dom.httpErrorRateChartCtx) { console.error("One or more chart canvas elements not found."); return; }

             Chart.defaults.color = 'var(--text-medium)';
             Chart.defaults.borderColor = 'var(--border-color-medium)';
             Chart.defaults.font.family = "var(--font-family-base)";
             Chart.defaults.font.size = 11; // Smaller default font

             const commonTooltipOptions = {
                 backgroundColor: 'var(--bg-tooltip)',
                 titleFont: { weight: '600', size: 13 },
                 bodyFont: { size: 11 },
                 padding: 12, boxPadding: 6, cornerRadius: var(--border-radius-sm),
                 borderColor: 'var(--border-color-strong)', borderWidth: 1,
                 displayColors: true, usePointStyle: true,
             };
             const commonLegendOptions = {
                 position: 'bottom',
                 labels: { padding: 18, boxWidth: 10, font: { size: 11 }, usePointStyle: true }
             };
             const commonXAxisOptions = {
                 ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 15, font: { size: 10 }, color: 'var(--text-dark)' },
                 grid: { display: false }
             };
             const commonYAxisOptions = {
                 ticks: { beginAtZero: true, font: { size: 10 }, precision: 0, color: 'var(--text-medium)' },
                 grid: { color: 'var(--border-color-medium)', drawTicks: false, borderDash: [3, 4] }
             };

             // --- Rates Chart (Line) ---
             const ratesOpts = { responsive: true, maintainAspectRatio: false, animation: { duration: 200 }, plugins: { legend: commonLegendOptions, tooltip: { ...commonTooltipOptions, mode: 'index', intersect: false } }, scales: { x: commonXAxisOptions, yReq: { ...commonYAxisOptions, type: 'linear', position: 'left', title: { display: false }, ticks:{color:'var(--accent-indigo)'} }, yProcFail: { ...commonYAxisOptions, type: 'linear', position: 'right', title: { display: false }, grid: { drawOnChartArea: false }, ticks:{color:'var(--accent-green)'} } }, elements: { line: { tension: 0.3, borderWidth: 2 }, point: { radius: 0, hitRadius: 10, hoverRadius: 5 } }, interaction: { mode: 'nearest', axis: 'x', intersect: false } };
             chartInstances.rates = new Chart(dom.ratesChartCtx, { type: 'line', data: { labels: [], datasets: [ { label: 'Reqs/sec', data: [], borderColor: 'var(--accent-indigo)', backgroundColor: 'rgba(92, 107, 192, 0.1)', fill: false, yAxisID: 'yReq' }, { label: 'Proc/sec', data: [], borderColor: 'var(--accent-green)', backgroundColor: 'rgba(76, 175, 80, 0.1)', fill: false, yAxisID: 'yProcFail' }, { label: 'Fail/sec', data: [], borderColor: 'var(--accent-red)', backgroundColor: 'rgba(244, 67, 54, 0.1)', fill: false, yAxisID: 'yProcFail' } ] }, options: ratesOpts });

             // --- Message Status Chart (Stacked Area) ---
             const msgStatusOpts = { responsive: true, maintainAspectRatio: false, animation: { duration: 200 }, plugins: { legend: commonLegendOptions, tooltip: { ...commonTooltipOptions, mode: 'index', intersect: false } }, scales: { x: commonXAxisOptions, y: { ...commonYAxisOptions, stacked: true, title: { display: false } } }, elements: { line: { tension: 0.1, borderWidth: 1.5, fill: 'start' }, point: { radius: 0, hitRadius: 10, hoverRadius: 5 } }, interaction: { mode: 'index', axis: 'x', intersect: false } };
             chartInstances.messageStatus = new Chart(dom.messageStatusChartCtx, { type: 'line', data: { labels: [], datasets: [ { label: 'Failed', data: [], borderColor: 'var(--status-error)', backgroundColor: 'rgba(244, 67, 54, 0.5)', order: 3 }, { label: 'Processing', data: [], borderColor: 'var(--status-processing)', backgroundColor: 'rgba(92, 107, 192, 0.5)', order: 2 }, { label: 'Pending', data: [], borderColor: 'var(--status-warning)', backgroundColor: 'rgba(255, 152, 0, 0.5)', order: 1 }, /* Exclude 'Processed' from stack as it grows too large, keep if needed: { label: 'Processed', data: [], borderColor: 'var(--status-success)', backgroundColor: 'rgba(76, 175, 80, 0.3)', order: 0 } */ ] }, options: msgStatusOpts });

             // --- Performance Chart (Line, Multi-Axis) ---
             const perfOpts = { responsive: true, maintainAspectRatio: false, animation: { duration: 200 }, plugins: { legend: commonLegendOptions, tooltip: { ...commonTooltipOptions, mode: 'index', intersect: false } }, scales: { x: commonXAxisOptions, yCpu: { ...commonYAxisOptions, type: 'linear', position: 'left', title: { display: true, text: 'CPU (%)', color: 'var(--accent-cyan)', font:{size:10, weight:'500'} }, ticks: { color: 'var(--accent-cyan)', precision: 1 }, grid: { color: 'rgba(0, 188, 212, 0.1)' } }, yMem: { ...commonYAxisOptions, type: 'linear', position: 'right', title: { display: true, text: 'Memory (%)', color: 'var(--accent-teal)', font:{size:10, weight:'500'} }, ticks: { color: 'var(--accent-teal)', precision: 1 }, grid: { drawOnChartArea: false } } }, elements: { line: { tension: 0.3, borderWidth: 2 }, point: { radius: 0, hitRadius: 10, hoverRadius: 5 } }, interaction: { mode: 'index', axis: 'x', intersect: false } };
             chartInstances.performance = new Chart(dom.performanceChartCtx, { type: 'line', data: { labels: [], datasets: [ { label: 'API Process CPU %', data: [], borderColor: 'var(--accent-cyan)', yAxisID: 'yCpu', backgroundColor: 'rgba(0, 188, 212, 0.1)', fill: 'start' }, { label: 'System CPU %', data: [], borderColor: 'var(--accent-blue)', yAxisID: 'yCpu', backgroundColor: 'rgba(33, 150, 243, 0.1)', fill: 'start' }, { label: 'System Memory %', data: [], borderColor: 'var(--accent-teal)', yAxisID: 'yMem', backgroundColor: 'rgba(38, 166, 154, 0.1)', fill: 'start' } ] }, options: perfOpts });

             // --- Requests by Route (Horizontal Bar) ---
             const routeOpts = { responsive: true, maintainAspectRatio: false, indexAxis: 'y', animation: { duration: 300 }, plugins: { legend: { display: false }, tooltip: { ...commonTooltipOptions, mode: 'index', intersect: true, callbacks: { label: (context) => ` Count: ${formatNumber(context.parsed.x)}` } } }, scales: { x: { ...commonYAxisOptions, title:{ display: true, text: 'Total Requests', font:{size: 10} } }, y: { ...commonXAxisOptions, ticks: { font: { size: 10 }, color:'var(--text-medium)' }, grid: { display: false } } } };
             chartInstances.requestsByRoute = new Chart(dom.requestsByRouteChartCtx, { type: 'bar', data: { labels: [], datasets: [{ label: 'Count', data: [], backgroundColor: 'var(--accent-indigo)', hoverBackgroundColor: 'var(--accent-blue)', borderRadius: 3, barPercentage: 0.8, categoryPercentage: 0.7 }] }, options: routeOpts });

             // --- Requests by Status (Doughnut) ---
             const statusOpts = { responsive: true, maintainAspectRatio: false, animation: { duration: 300, animateRotate: true, animateScale: true }, cutout: '65%', plugins: { legend: { position: 'right', labels: { padding: 15, boxWidth: 12, font: { size: 11 } } }, tooltip: { ...commonTooltipOptions, callbacks: { label: (context) => ` ${context.label}: ${formatNumber(context.parsed)} (${((context.parsed / context.chart.getDatasetMeta(0).total) * 100).toFixed(1)}%)` } } } };
             chartInstances.requestsByStatus = new Chart(dom.requestsByStatusChartCtx, { type: 'doughnut', data: { labels: [], datasets: [{ label: 'Count', data: [], backgroundColor: [], // Set dynamically
                 borderWidth: 2, borderColor: 'var(--bg-card)', hoverOffset: 12, hoverBorderColor: 'var(--text-light)' }] }, options: statusOpts });

             // --- HTTP Error Rate Chart (Line) ---
             const errRateOpts = { responsive: true, maintainAspectRatio: false, animation: { duration: 200 }, plugins: { legend: { display: false }, tooltip: { ...commonTooltipOptions, mode: 'index', intersect: false, callbacks: { label: (context) => ` ${context.dataset.label}: ${formatDecimal(context.parsed.y, 1)}%` } } }, scales: { x: commonXAxisOptions, y: { ...commonYAxisOptions, suggestedMax: 10, title: { display: true, text: 'Error Rate (%)', font:{size: 10}}, ticks: { callback: (value) => value + '%' } } }, elements: { line: { tension: 0.2, borderWidth: 2 }, point: { radius: 0, hitRadius: 10, hoverRadius: 5 } }, interaction: { mode: 'index', axis: 'x', intersect: false } };
             chartInstances.httpErrorRate = new Chart(dom.httpErrorRateChartCtx, { type: 'line', data: { labels: [], datasets: [{ label: 'HTTP Err % (4xx+)', data: [], borderColor: 'var(--accent-red)', backgroundColor: 'rgba(244, 67, 54, 0.2)', fill: true }] }, options: errRateOpts });

             console.info("All charts initialized.");
        }

        // --- Data Fetching & Processing ---
        async function fetchDashboardData() {
             if (!initialLoadComplete && dom.statusIndicator) { updateStatusIndicator('fetching', 'Fetching initial data...'); }
             else if (dom.statusIndicator && !dom.statusIndicator.classList.contains('error')) { updateStatusIndicator('fetching', 'Fetching stats...'); }

             console.debug(`[${DateTime.now().toFormat('HH:mm:ss')}] Fetching ${CONFIG.API_DASHBOARD_DATA_URL}`);
             try {
                 const response = await fetch(CONFIG.API_DASHBOARD_DATA_URL);
                 const data = await response.json(); // Assume JSON response

                 if (!response.ok) {
                     // Try to get error message from response, fallback to statusText
                     const errorMsg = data?.error || data?.detail || `Server returned status ${response.status}`;
                     throw new Error(errorMsg);
                 }

                 // Check for API-level error reported within the data
                 if (data.last_api_error) {
                     console.warn("API reported an error:", data.last_api_error);
                     updateApiErrorUI(data.last_api_error);
                     // Don't necessarily stop UI updates, some data might still be valid
                 } else {
                      // Clear previous error if current fetch is successful and no error reported
                      if (lastKnownApiError) updateApiErrorUI(null);
                 }

                 // Validate core data presence
                 if (!data.latest_stats || Object.keys(data.latest_stats).length === 0) {
                     console.warn("Dashboard data received, but 'latest_stats' is missing or empty.");
                     // Handle this gracefully, maybe show a specific message?
                     // For now, update UI with available data, cards might show '--'
                 }

                 // Update UI with the received data
                 updateDashboardUI(data);
                 lastSuccessfulDataFetch = data.last_successful_stats_fetch || data.last_successful_queues_fetch || DateTime.now().toISO(); // Use server time if available
                 updateStatusIndicator(); // Update based on success and timestamps

                 // Handle log viewer state based on dashboard data
                 handleLogStateFromDashboard(data);

                 if (!initialLoadComplete) {
                     initialLoadComplete = true;
                     console.info("Initial dashboard data load complete.");
                     // Fetch initial log content *after* dashboard data sets the filename
                     if (currentLogFilename) {
                          fetchLogData(false, true); // Force initial log fetch
                     }
                 }

             } catch (error) {
                 console.error(`Dashboard data fetch failed: ${error.message}`);
                 // Update UI to show a dashboard-level connection error
                 updateApiErrorUI({ message: `Dashboard connection error: ${error.message}`, type: "dashboard_fetch", timestamp: DateTime.now().toISO() });
                 updateStatusIndicator(); // Update status based on error
                 // Potentially clear parts of the UI or show stale data indicators?
                 // clearUI(); // Optionally clear everything on fetch failure
             }
        }

        function handleLogStateFromDashboard(data) {
            // Sync log auto-refresh toggle state
            if (dom.logAutoRefreshToggle && data.log_auto_refresh_enabled !== undefined) {
                logAutoRefreshEnabled = data.log_auto_refresh_enabled;
                dom.logAutoRefreshToggle.checked = logAutoRefreshEnabled;
                // Restart timer based on potentially changed state
                 startLogAutoRefreshTimer();
            }

            // Update current filename and "Load Older" capability
             currentLogFilename = data.current_log_filename || null;
             canLoadOlderLogs = !!data.log_next_fetch_start_line; // Convert to boolean

             if (dom.logFilenameDisplay) {
                 dom.logFilenameDisplay.textContent = currentLogFilename || 'N/A';
                 if (currentLogFilename) dom.logFilenameDisplay.classList.remove('na');
                 else dom.logFilenameDisplay.classList.add('na');
             }
             if (dom.loadOlderLogsBtn) {
                 dom.loadOlderLogsBtn.disabled = !canLoadOlderLogs || isFetchingLogs;
             }
              if (dom.refreshLogsBtn) {
                 dom.refreshLogsBtn.disabled = !currentLogFilename || isFetchingLogs;
              }

            // If the backend reports a log fetch error, display it
            if (data.log_fetch_error && !lastKnownApiError?.message.includes('Log file')) { // Avoid duplicate error display
                 setLogOverlay(`Log Error: ${data.log_fetch_error}`, true);
                 if (dom.logStatusText) dom.logStatusText.textContent = `Error: ${data.log_fetch_error}`;
            }
        }

        async function fetchLogData(fetchOlder = false, isInitialFetch = false) {
             if (!currentLogFilename) {
                 console.debug("fetchLogData skipped: No log file selected.");
                 updateLogViewerUI({ lines: [], filename: null }, false); // Clear UI if no file
                 return;
             }
             if (isFetchingLogs) {
                 console.debug(`fetchLogData skipped (${fetchOlder ? 'older' : 'latest'}): Already fetching.`);
                 return;
             }

             isFetchingLogs = true;
             const userAction = fetchOlder || !logAutoRefreshEnabled; // Was this likely triggered by user?
             if (userAction || isInitialFetch) { // Show visual cue for user actions or first load
                setLogOverlay(fetchOlder ? 'Loading older entries...' : 'Fetching latest logs...', true);
             }
             if(dom.logStatusText) dom.logStatusText.textContent = fetchOlder ? 'Loading older...' : 'Refreshing...';
             if(dom.loadOlderLogsBtn) dom.loadOlderLogsBtn.disabled = true;
             if(dom.refreshLogsBtn) dom.refreshLogsBtn.disabled = true;

             const url = fetchOlder ? CONFIG.API_FETCH_OLDER_LOGS_URL : CONFIG.API_LOG_DATA_URL;
             console.debug(`[${DateTime.now().toFormat('HH:mm:ss')}] Fetching ${url}${fetchOlder ? ' (older)' : ' (latest)'}`);

             try {
                 const response = await fetch(url);
                 const logData = await response.json();

                 if (!response.ok) {
                      const errorMsg = logData?.error || logData?.detail || `Server returned status ${response.status}`;
                      throw new Error(errorMsg);
                 }

                 // Check for specific log fetch error from backend response
                 if (logData.log_fetch_error) {
                      console.warn(`Log fetch for ${logData.filename} reported error: ${logData.log_fetch_error}`);
                      setLogOverlay(`Error: ${logData.log_fetch_error}`, true); // Show error in overlay
                 } else {
                      setLogOverlay('', false); // Clear overlay on success
                 }

                 updateLogViewerUI(logData, fetchOlder); // Update UI with new lines/state

                 // Update state based on response
                  currentLogFilename = logData.filename || null; // Update filename just in case
                  canLoadOlderLogs = !!logData.next_fetch_start_line;

             } catch (error) {
                 console.error(`Log data fetch failed (${fetchOlder ? 'older' : 'latest'}): ${error.message}`);
                 setLogOverlay(`Error fetching logs: ${error.message}`, true);
                 if(dom.logStatusText) dom.logStatusText.textContent = `Error: ${error.message.substring(0, 100)}`;
                 // Don't clear existing logs on error, just show message
             } finally {
                 isFetchingLogs = false;
                 // Re-enable buttons based on latest state
                 if(dom.loadOlderLogsBtn) dom.loadOlderLogsBtn.disabled = !canLoadOlderLogs;
                 if(dom.refreshLogsBtn) dom.refreshLogsBtn.disabled = !currentLogFilename; // Re-enable if a file is selected
                  // Clear status text if it was just 'Loading' or 'Refreshing'
                 if(dom.logStatusText && (dom.logStatusText.textContent.startsWith('Loading') || dom.logStatusText.textContent.startsWith('Refreshing'))) {
                    dom.logStatusText.textContent = `Last updated: ${DateTime.now().toFormat('HH:mm:ss')}`;
                 }
             }
        }

        // --- Core UI Update Function ---
        function updateDashboardUI(data) {
            console.debug("Updating dashboard UI with data:", data);

            // --- Cards Update ---
            if (data.latest_stats) {
                const stats = data.latest_stats;
                const sys = stats.system || {};

                // Message Stats
                updateCardValue(dom.pendingMsgs, safeGet(stats, 'messages_pending'));
                updateCardValue(dom.processingMsgs, safeGet(stats, 'messages_processing'));
                updateCardValue(dom.failedMsgs, safeGet(stats, 'messages_failed'));
                updateCardValue(dom.processedMsgs, safeGet(stats, 'messages_processed'));
                updateCardValue(dom.totalMsgs, safeGet(stats, 'messages_total')); // Assuming API provides this

                // Request & System Stats
                updateCardValue(dom.totalRequests, safeGet(stats, 'requests_total'));
                updateCardValue(dom.uptime, safeGet(stats, 'uptime_str'), formatUptime);
                updateCardValue(dom.processCpu, safeGet(sys, 'process_cpu_percent'), formatPercentage);
                updateCardValue(dom.processMem, safeGet(sys, 'process_memory_mb'), (v) => formatMemory(v, 'MB'));
                updateCardValue(dom.systemCpu, safeGet(sys, 'cpu_percent'), formatPercentage);
                updateCardValue(dom.systemMem, safeGet(sys, 'memory_percent'), formatPercentage);
                updateCardValue(dom.filesThreads, formatFilesThreads(safeGet(sys, 'process_num_fds'), safeGet(sys, 'process_num_threads')), v => v); // Pass raw string

                // HTTP Error Rate Card (uses history)
                const errorRateHistory = safeGet(data, 'history.http_error_rate_history', []);
                updateCardValue(dom.httpErrorRate, errorRateHistory[errorRateHistory.length - 1], formatPercentage);
            } else {
                 console.warn("No 'latest_stats' data found in response. Cards may not update.");
                 // Optionally clear specific cards if stats are missing
            }

            // Queue Count Card
            updateCardValue(dom.totalQueues, data.latest_queues?.length);

            // --- Info Tables Update ---
            updateSystemInfoTable(safeGet(data, 'latest_stats.system', {}));
            updateBrokerInfoTable(safeGet(data, 'latest_stats.broker_config', {})); // Assuming this key exists
            updateQueuesTable(data.latest_queues || []);
            updateDiskInfoTable(safeGet(data, 'latest_stats.system.disk_usage', []));

            // --- Charts Update ---
            if (data.history) {
                 const hist = data.history;
                 updateChartData(chartInstances.rates, hist.time_labels, [hist.request_rate_history, hist.processed_rate_history, hist.failed_rate_history]);
                 updateChartData(chartInstances.messageStatus, hist.time_labels, [
                     safeGet(hist, 'message_status.failed', []),
                     safeGet(hist, 'message_status.processing', []),
                     safeGet(hist, 'message_status.pending', []),
                 ]);
                  updateChartData(chartInstances.performance, hist.time_labels, [
                     safeGet(hist, 'performance.process_cpu', []),
                     safeGet(hist, 'performance.system_cpu', []),
                     safeGet(hist, 'performance.system_memory', []), // Matching dataset order in init
                 ]);
                 updateChartData(chartInstances.httpErrorRate, hist.time_labels, [hist.http_error_rate_history]);

                // Update categorical charts (which use totals from latest_stats)
                if(data.latest_stats) {
                    updateRequestsByStatusChart(safeGet(data.latest_stats, 'requests_by_status', {}));
                    updateRequestsByRouteChart(safeGet(data.latest_stats, 'requests_by_route', {}));
                }
            } else {
                 console.warn("No 'history' data found in response. Time-series charts may not update.");
            }
        }

        // --- Table Population Functions ---
        function populateTable(tbodyElement, dataRows, columns) {
             if (!tbodyElement) return;
             tbodyElement.innerHTML = ''; // Clear existing rows
             if (!dataRows || dataRows.length === 0) {
                 tbodyElement.innerHTML = `<tr><td colspan="${columns.length}" class="no-data">(No data available)</td></tr>`;
                 return;
             }
             dataRows.forEach(rowData => {
                 const tr = tbodyElement.insertRow();
                 columns.forEach(col => {
                     const td = tr.insertCell();
                     let value = safeGet(rowData, col.key, '--');
                     if (col.formatter) {
                         value = col.formatter(value, rowData); // Pass full row data if needed
                     }
                      // Safely render HTML if formatter returns it
                     if (typeof value === 'string' && (value.includes('<') || value.includes('&'))) {
                         // Basic check for HTML, consider a more robust check or explicit flag
                         // Use DOMPurify here if complex HTML is possible and security is paramount
                          td.innerHTML = value; // Assume simple/safe HTML from formatters
                     } else {
                          td.textContent = value;
                     }

                     if(col.class) td.classList.add(col.class);
                 });
             });
        }

        function createDiskUsageBar(usageData) {
             const percent = parseFloat(safeGet(usageData, 'percent', 0));
             const used = formatBytes(safeGet(usageData, 'used'));
             const free = formatBytes(safeGet(usageData, 'free'));
             let barClass = '';
             if (percent > 90) barClass = 'crit';
             else if (percent > 75) barClass = 'warn';
             // Use markupsafe.Markup equivalent in JS (or just raw HTML string for simple cases)
             return `
                 <div class="disk-usage-bar-container">
                     <span class="disk-usage-text">${formatDecimal(percent, 1)}% Used</span>
                     <div class="disk-usage-bar">
                         <div class="disk-usage-fill ${barClass}" style="width: ${percent}%;"></div>
                     </div>
                 </div>
                 <div class="disk-usage-text" style="font-size: 0.85em; color: var(--text-dark);">${used} used / ${free} free</div>
             `;
        }

        function updateSystemInfoTable(sysData) {
            populateTable(dom.systemInfoTableBody, [sysData], [ // Wrap sysData in array as it's one row conceptually
                { key: 'hostname', label: 'Hostname' },
                { key: 'os_platform', label: 'OS' },
                { key: 'cpu_cores', label: 'CPU Cores' },
                { key: 'load_average', label: 'Load Avg (1m, 5m, 15m)', formatter: formatLoadAvg },
                { key: 'memory_total', label: 'Total Memory', formatter: formatBytes },
                { key: 'memory_available', label: 'Available Memory', formatter: formatBytes },
                 // Add Python version if available
                { key: 'python_version', label: 'Python Version' },
            ].map(c => ({ key: c.key, formatter: c.formatter })) // Extract needed info for populateTable
            .filter(c => safeGet(sysData, c.key) !== null) // Only show rows with data
            .map(c => { // Rebuild for display labels
                 const labels = { hostname: 'Hostname', os_platform: 'OS', cpu_cores: 'CPU Cores', load_average: 'Load Avg', memory_total: 'Total Memory', memory_available: 'Available Memory', python_version: 'Python Ver.' };
                 return { key: c.key, label: labels[c.key] || c.key, formatter: c.formatter };
            }));

            // Manually create rows for table structure if needed
             if (dom.systemInfoTableBody) {
                 dom.systemInfoTableBody.innerHTML = ''; // Clear first
                 const info = [
                      { label: 'Hostname', value: safeGet(sysData, 'hostname', '--') },
                      { label: 'Operating System', value: safeGet(sysData, 'os_platform', '--') },
                      { label: 'CPU Cores', value: safeGet(sysData, 'cpu_cores', '--') },
                      { label: 'Load Average', value: formatLoadAvg(safeGet(sysData, 'load_average')) },
                      { label: 'Total Memory', value: formatBytes(safeGet(sysData, 'memory_total')) },
                      { label: 'Available Memory', value: formatBytes(safeGet(sysData, 'memory_available')) },
                      { label: 'Python Version', value: safeGet(sysData, 'python_version', '--') },
                      // Add Dashboard Uptime
                      { label: 'Dashboard Uptime', value: formatRelativeTime(safeGet(sysData, 'dashboard_start_time')) } // Requires backend to add this
                 ];
                 info.forEach(item => {
                     if (item.value !== '--' && item.value !== null && item.value !== undefined) {
                          const tr = dom.systemInfoTableBody.insertRow();
                          const th = document.createElement('th');
                          th.textContent = item.label;
                          tr.appendChild(th);
                          const td = tr.insertCell();
                          td.textContent = item.value;
                     }
                 });
                  if (dom.systemInfoTableBody.rows.length === 0) {
                      dom.systemInfoTableBody.innerHTML = `<tr><td colspan="2" class="no-data">(No system info)</td></tr>`;
                  }
             }
        }

        function updateBrokerInfoTable(brokerData) {
             // Similar manual row creation as updateSystemInfoTable
             if (dom.brokerInfoTableBody) {
                  dom.brokerInfoTableBody.innerHTML = '';
                  const info = Object.entries(brokerData || {}).map(([key, value]) => ({ label: key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()), value: value }));

                  info.forEach(item => {
                     const tr = dom.brokerInfoTableBody.insertRow();
                     const th = document.createElement('th');
                     th.textContent = item.label;
                     tr.appendChild(th);
                     const td = tr.insertCell();
                     // Display complex values (like lists/dicts) as JSON string
                     if (typeof item.value === 'object' && item.value !== null) {
                         td.innerHTML = `<code>${escapeHtml(JSON.stringify(item.value))}</code>`;
                     } else {
                          td.textContent = String(item.value);
                     }
                 });
                 if (dom.brokerInfoTableBody.rows.length === 0) {
                      dom.brokerInfoTableBody.innerHTML = `<tr><td colspan="2" class="no-data">(No broker config)</td></tr>`;
                  }
             }
        }

        function updateQueuesTable(queuesData) {
            if(dom.queueCountSpan) dom.queueCountSpan.textContent = queuesData.length;
            populateTable(dom.queuesInfoTableBody, queuesData, [
                { key: 'name', label: 'Name', formatter: (val) => `<code>${escapeHtml(val)}</code>` },
                { key: 'messages_total', label: 'Total Msgs', formatter: formatNumber }, // Use appropriate key from API
                { key: 'created_at', label: 'Created', formatter: formatRelativeTime } // Use appropriate key from API
            ]);
        }

        function updateDiskInfoTable(diskData) {
            populateTable(dom.diskInfoTableBody, diskData, [
                { key: 'mountpoint', label: 'Mountpoint', formatter: (val) => `<code>${escapeHtml(val)}</code>` },
                { key: 'percent', label: 'Usage', formatter: (val, row) => createDiskUsageBar(row) }, // Use custom formatter
                { key: 'free', label: 'Free Space', formatter: formatBytes }
            ]);
        }

        // --- Chart Specific Update Functions ---
        function updateRequestsByStatusChart(reqByStatus) {
            if (!chartInstances.requestsByStatus || !reqByStatus) return;
            const labels = Object.keys(reqByStatus).sort((a,b) => parseInt(a) - parseInt(b)); // Sort by status code
            const data = labels.map(status => reqByStatus[status]);
            updateChartData(chartInstances.requestsByStatus, labels, [data]);
        }

        function updateRequestsByRouteChart(reqByRoute) {
            if (!chartInstances.requestsByRoute || !reqByRoute) return;
            // Sort routes by count descending, take top 15
            const sortedRoutes = Object.entries(reqByRoute)
                                     .sort(([, countA], [, countB]) => countB - countA)
                                     .slice(0, 15);
            const labels = sortedRoutes.map(([route]) => route);
            const data = sortedRoutes.map(([, count]) => count);
            updateChartData(chartInstances.requestsByRoute, labels, [data]);
        }


        // --- Log Viewer Functions ---
        function updateLogViewerUI(logData, wasPrepended) { // wasPrepended means older logs were loaded
             if (!dom.logContentArea) return;

             const { lines = [], filename = null } = logData;
             const shouldPreserveScroll = !wasPrepended && isScrolledToBottom(dom.logContentArea);

             if (filename !== currentLogFilename && !isInitialFetch) { // filename changed from backend, likely cleared
                 dom.logContentArea.innerHTML = ''; // Clear existing content
                 if (dom.logInitialMessage) {
                     dom.logInitialMessage.textContent = filename ? "(Loading new log file...)" : "(No log file selected)";
                     dom.logContentArea.appendChild(dom.logInitialMessage);
                     dom.logInitialMessage.style.display = 'block';
                 }
                 currentLogFilename = filename; // Update local cache
                 // Fetch new file content immediately? Maybe wait for next cycle or user action.
             }

             // Remove the initial message if it exists and we have lines
             if (dom.logInitialMessage && lines.length > 0) {
                 dom.logInitialMessage.style.display = 'none';
             }

             if (lines.length > 0) {
                 const fragment = document.createDocumentFragment();
                 lines.forEach(lineData => {
                     const lineElement = createLogLineElement(lineData);
                     if (lineElement) {
                         fragment.appendChild(lineElement);
                     }
                 });

                 if (wasPrepended) { // Appending older logs to the end of view (top of content area)
                     dom.logContentArea.insertBefore(fragment, dom.logContentArea.firstChild);
                     // Try to maintain scroll position relative to the old top element
                     // This is tricky, might need more sophisticated logic if jarring
                 } else { // Prepending newer logs to the start of view (bottom of content area)
                     dom.logContentArea.appendChild(fragment);
                 }

                  // Apply filtering/search to newly added lines (and potentially existing ones)
                  applyLogFilterAndSearch();
             } else if (!wasPrepended && dom.logContentArea.children.length === 0) {
                 // No new lines received, and log area is empty (and not loading older)
                 if (dom.logInitialMessage) {
                     dom.logInitialMessage.textContent = currentLogFilename ? "(Log file appears empty or filter matches no lines)" : "(No log file selected)";
                     dom.logInitialMessage.style.display = 'block';
                 }
             }

             // Trim excess log lines from the DOM to prevent performance issues
             const maxLogLinesInDom = CONFIG.LOG_CHUNK_SIZE * 5; // Keep ~5 chunks in DOM
             while (dom.logContentArea.children.length > maxLogLinesInDom) {
                 if (wasPrepended) { // Removing oldest lines (from the bottom)
                     dom.logContentArea.removeChild(dom.logContentArea.lastElementChild);
                 } else { // Removing oldest lines (from the top)
                      if (dom.logContentArea.firstChild && dom.logContentArea.firstChild !== dom.logInitialMessage) {
                         dom.logContentArea.removeChild(dom.logContentArea.firstChild);
                      } else {
                          break; // Avoid removing initial message
                      }
                 }
             }

             // Scroll to bottom if it was previously scrolled to bottom (for auto-refresh)
             if (shouldPreserveScroll && !wasPrepended) {
                 scrollToBottom(dom.logContentArea);
             }

              // Update status text (e.g., last updated time)
              if (dom.logStatusText && !logData.log_fetch_error) {
                  dom.logStatusText.textContent = `Last updated: ${DateTime.now().toFormat('HH:mm:ss')}`;
              }
        }

        function createLogLineElement(lineData) {
             if (!lineData || typeof lineData !== 'object') {
                 console.warn("Invalid lineData received:", lineData);
                 return null; // Skip invalid lines
             }
             const { timestamp, level = 'info', message = '' } = lineData;
             const lineDiv = document.createElement('div');
             lineDiv.classList.add('log-line');
             lineDiv.dataset.level = level.toLowerCase(); // Store level for filtering

             const timeSpan = document.createElement('span');
             timeSpan.classList.add('log-line-timestamp');
             // Format time only, date is usually implied by file
             timeSpan.textContent = timestamp ? DateTime.fromISO(timestamp).toFormat('HH:mm:ss.SSS') : '??:??:??';
             lineDiv.appendChild(timeSpan);

             const levelSpan = document.createElement('span');
             levelSpan.classList.add('log-line-level', level.toLowerCase());
             levelSpan.textContent = level.toUpperCase();
             lineDiv.appendChild(levelSpan);

             const msgSpan = document.createElement('span');
             msgSpan.classList.add('log-line-message');
             // IMPORTANT: Escape message content to prevent XSS if logs contain HTML/JS
             // Use textContent for safety. If highlighting is needed, do it carefully.
              msgSpan.textContent = message; // Safe default
              // Apply highlighting if needed *after* setting textContent
              applyHighlighting(msgSpan, message, logSearchTerm);

             lineDiv.appendChild(msgSpan);
             return lineDiv;
        }

         function applyLogFilterAndSearch() {
             if (!dom.logContentArea) return;
             const searchTerm = logSearchTerm.toLowerCase();
             const filterLevel = logFilterLevel;
             let visibleCount = 0;

             // Iterate through existing log lines
             const lines = dom.logContentArea.querySelectorAll('.log-line');
             lines.forEach(line => {
                 const lineLevel = line.dataset.level || 'info';
                 const lineMessageElement = line.querySelector('.log-line-message');
                 const lineMessage = lineMessageElement ? lineMessageElement.textContent.toLowerCase() : ''; // Use textContent for search

                 // Check level filter
                 const levelMatch = !filterLevel || (filterLevel === lineLevel);

                 // Check search term filter
                 const searchMatch = !searchTerm || lineMessage.includes(searchTerm);

                 // Show/hide line
                 if (levelMatch && searchMatch) {
                     line.classList.remove('hidden');
                     visibleCount++;
                     // Apply/remove highlighting based *only* on search term match
                     if (lineMessageElement) {
                         applyHighlighting(lineMessageElement, lineMessageElement.textContent, searchTerm);
                     }
                 } else {
                     line.classList.add('hidden');
                     // Remove highlighting if hidden
                      if (lineMessageElement) {
                         applyHighlighting(lineMessageElement, lineMessageElement.textContent, ''); // Clear highlighting
                      }
                 }
             });
              console.debug(`Log filter applied. Visible lines: ${visibleCount}/${lines.length}. Filter: level='${filterLevel}', search='${searchTerm}'`);
              // Update status if needed (e.g., "Showing X of Y lines")
               if (dom.logInitialMessage && visibleCount === 0 && lines.length > 0) {
                   dom.logInitialMessage.textContent = "(Filter matches no log lines)";
                   dom.logInitialMessage.style.display = 'block';
               } else if (dom.logInitialMessage && visibleCount > 0) {
                   dom.logInitialMessage.style.display = 'none';
               }
         }

         function applyHighlighting(element, originalText, searchTerm) {
             // Simple text highlighting. For complex cases, use libraries or more robust regex.
             if (!element) return;
             if (!searchTerm || searchTerm.length < 1) {
                 element.textContent = originalText; // Restore original if no search term
                 return;
             }
             const lowerText = originalText.toLowerCase();
             const lowerSearchTerm = searchTerm.toLowerCase();
             let startIndex = 0;
             let resultHtml = '';
             let index = lowerText.indexOf(lowerSearchTerm, startIndex);

             while (index !== -1) {
                 // Append text before the match (escaped)
                 resultHtml += escapeHtml(originalText.substring(startIndex, index));
                 // Append the highlighted match (escaped)
                 resultHtml += `<span class="log-highlight">${escapeHtml(originalText.substring(index, index + searchTerm.length))}</span>`;
                 startIndex = index + searchTerm.length;
                 index = lowerText.indexOf(lowerSearchTerm, startIndex);
             }
             // Append remaining text (escaped)
             resultHtml += escapeHtml(originalText.substring(startIndex));
             element.innerHTML = resultHtml;
         }

        function isScrolledToBottom(element) {
            if (!element) return false;
            // Check if scroll position is close to the bottom
            const threshold = 5; // Pixels threshold
            return element.scrollHeight - element.scrollTop - element.clientHeight < threshold;
        }

        function scrollToBottom(element) {
            if (!element) return;
            element.scrollTop = element.scrollHeight;
        }

        // --- Status & Error Handling ---
        function updateApiErrorUI(errorData) {
             lastKnownApiError = errorData; // Store the latest error globally
             if (!dom.lastErrorCard || !dom.lastErrorMessage || !dom.lastErrorTimestamp) return;

             if (errorData) {
                 dom.lastErrorMessage.textContent = errorData.message || 'Unknown error';
                 dom.lastErrorTimestamp.textContent = `Type: ${errorData.type || 'generic'} | Time: ${formatDateTime(errorData.timestamp)}`;
                 dom.lastErrorCard.style.display = 'flex'; // Show the card
             } else {
                 dom.lastErrorCard.style.display = 'none'; // Hide the card
             }
             // Also update the main status indicators
             updateStatusIndicator();
        }

        function updateStatusIndicator(forceState = null, forceText = null) {
             let status = 'init'; // 'init', 'live', 'stale', 'error', 'fetching'
             let statusText = 'Initializing...';
             const now = DateTime.now();

             if (forceState) {
                 status = forceState;
                 statusText = forceText || status.charAt(0).toUpperCase() + status.slice(1);
             } else if (lastKnownApiError) {
                 status = 'error';
                 statusText = `API Error (${lastKnownApiError.type || 'generic'})`;
                 // Add more detail on hover/title?
             } else if (lastSuccessfulDataFetch) {
                 const lastFetchTime = DateTime.fromISO(lastSuccessfulDataFetch);
                 if (lastFetchTime.isValid) {
                    const diffSeconds = now.diff(lastFetchTime, 'seconds').seconds;
                    // Consider live if updated within 2.5x the polling interval
                    if (diffSeconds < (CONFIG.POLLING_INTERVAL_MS / 1000) * 2.5) {
                        status = 'live';
                        statusText = `Live (Updated ${lastFetchTime.toRelative()})`;
                    } else {
                        status = 'stale';
                        statusText = `Stale (Last update ${lastFetchTime.toRelative()})`;
                    }
                 } else {
                      status = 'stale'; // Invalid timestamp
                      statusText = 'Stale (Timestamp issue)';
                 }
             } else {
                  // Still initializing, no successful fetch yet
                  status = 'init';
                  statusText = 'Waiting for first data...';
             }

             // Update Header Indicator
             if (dom.statusIndicator) {
                 dom.statusIndicator.textContent = statusText;
                 dom.statusIndicator.className = `status-indicator ${status}`;
                 dom.statusIndicator.title = `Status: ${status} | Last Fetch: ${lastSuccessfulDataFetch || 'N/A'} | Error: ${lastKnownApiError?.message || 'None'}`;
             }

             // Update Footer Indicator
             if (dom.footerStatus) {
                  const icons = { init: '⏳', live: '✅', stale: '⚠️', error: '❌', fetching: '⏳' };
                  const footerClasses = { init: 'stale', live: 'success', stale: 'stale', error: 'error', fetching: 'stale' };
                  dom.footerStatus.innerHTML = `<span class="status-icon">${icons[status] || ''}</span>${statusText}`;
                  dom.footerStatus.className = `footer-status ${footerClasses[status] || 'stale'}`;
             }
        }


        // --- Event Listeners ---
        function setupEventListeners() {
            // Log Viewer Controls
            if (dom.refreshLogsBtn) {
                dom.refreshLogsBtn.addEventListener('click', () => {
                     console.log("Manual log refresh triggered.");
                     fetchLogData(false); // Fetch latest
                });
            }
            if (dom.loadOlderLogsBtn) {
                dom.loadOlderLogsBtn.addEventListener('click', () => {
                     console.log("Load older logs triggered.");
                     fetchLogData(true); // Fetch older
                });
            }
            if (dom.logAutoRefreshToggle) {
                 dom.logAutoRefreshToggle.addEventListener('change', async (e) => {
                     const enabled = e.target.checked;
                     console.log(`Toggling log auto-refresh to: ${enabled}`);
                     try {
                         const response = await fetch(CONFIG.API_TOGGLE_LOG_REFRESH_URL, {
                             method: 'POST',
                             headers: {'Content-Type': 'application/json'},
                             body: JSON.stringify({enabled: enabled})
                         });
                         if (!response.ok) {
                             const errorData = await response.json();
                             throw new Error(errorData.error || `Server error ${response.status}`);
                         }
                         const result = await response.json();
                         if (result.success) {
                             logAutoRefreshEnabled = result.enabled;
                             dom.logAutoRefreshToggle.checked = logAutoRefreshEnabled; // Ensure UI matches state
                             startLogAutoRefreshTimer(); // Restart timer with new setting
                             console.info(`Log auto-refresh successfully set to: ${logAutoRefreshEnabled}`);
                         } else { throw new Error("Toggle command rejected by server."); }
                     } catch (err) {
                         console.error("Failed to toggle log auto-refresh:", err);
                         // Revert checkbox on error to reflect actual state
                         e.target.checked = !enabled;
                         // Optionally show user feedback
                         if(dom.logStatusText) dom.logStatusText.textContent = "Error toggling refresh.";
                     }
                 });
            }
            if (dom.logSearchInput) {
                 dom.logSearchInput.addEventListener('input', () => {
                     clearTimeout(logSearchDebounceTimeout);
                     logSearchDebounceTimeout = setTimeout(() => {
                         logSearchTerm = dom.logSearchInput.value.trim();
                         console.debug(`Log search term changed: "${logSearchTerm}"`);
                         applyLogFilterAndSearch();
                     }, 300); // 300ms debounce
                 });
            }
            if (dom.logFilterLevel) {
                 dom.logFilterLevel.addEventListener('change', () => {
                     logFilterLevel = dom.logFilterLevel.value;
                     console.debug(`Log filter level changed: "${logFilterLevel}"`);
                     applyLogFilterAndSearch();
                 });
            }
            console.debug("Event listeners set up.");
        }

    </script>
     {% endraw %}
     {# ***** END RAW BLOCK FOR JS ***** #}
</body>
</html>
"""

# --- Flask Routes ---
@app.route('/')
def serve_dashboard():
    """Serves the main dashboard HTML page."""
    logger.info(f"Request for dashboard page from {request.remote_addr}")
    try:
        # Inject necessary config variables into the template
        return render_template_string( HTML_TEMPLATE,
            FETCH_STATS_INTERVAL_SECONDS=FETCH_STATS_INTERVAL_SECONDS,
            FETCH_LOGCONTENT_INTERVAL_SECONDS=FETCH_LOGCONTENT_INTERVAL_SECONDS,
            MAX_CHART_HISTORY=MAX_CHART_HISTORY,
            LOG_CHUNK_SIZE=LOG_CHUNK_SIZE
        )
    except Exception as e:
        logger.exception("Error rendering dashboard template")
        # Provide a minimal error page if template rendering fails
        return f"<h1>Internal Server Error</h1><p>Failed to render dashboard template: {e}</p>", 500

@app.route('/api/dashboard_data')
def get_dashboard_data():
    """API endpoint to provide the current state snapshot for the dashboard."""
    logger.debug("Request received for /api/dashboard_data")
    try:
        data = state.get_snapshot_for_dashboard()
        # Add dashboard start time to system info if available
        if data.get('latest_stats') and data['latest_stats'].get('system'):
            data['latest_stats']['system']['dashboard_start_time'] = state.server_start_time.isoformat()
        return jsonify(data)
    except Exception as e:
        logger.exception("Error preparing data for /api/dashboard_data")
        return jsonify({"error": "Failed to prepare dashboard data", "detail": str(e)}), 500

@app.route('/api/log_data')
def get_log_data():
    """API endpoint to get the latest log data chunk."""
    logger.debug("Request received for /api/log_data (latest)")
    # Note: Actual fetching is handled by the scheduled job or triggered elsewhere.
    # This endpoint just returns the current state of the log buffer.
    try:
        # Optionally trigger an immediate refresh if desired, but might conflict with scheduler
        # fetch_log_content_job(fetch_older=False)
        return jsonify(state.get_log_data_for_request())
    except Exception as e:
        logger.exception("Error preparing data for /api/log_data")
        return jsonify({"error": "Failed to prepare log data", "detail": str(e)}), 500

@app.route('/api/fetch_older_logs')
def get_older_logs():
    """API endpoint triggered by user to fetch older log entries."""
    logger.debug("Request received for /api/fetch_older_logs")
    # Trigger the job to fetch older logs. It runs async via the decorator/thread pool.
    # We return the *current* state immediately. The UI will update when the fetch completes.
    thread = threading.Thread(target=fetch_log_content_job, args=(True,), name="FetchOlderLogsThread")
    thread.start()
    logger.info("Dispatched background thread to fetch older logs.")
    try:
        # Return current state, UI will poll or update based on subsequent fetches
        return jsonify(state.get_log_data_for_request())
    except Exception as e:
        logger.exception("Error preparing data after triggering older log fetch")
        return jsonify({"error": "Failed to get log state after triggering fetch", "detail": str(e)}), 500

@app.route('/api/toggle_log_refresh', methods=['POST'])
def toggle_log_refresh():
    """API endpoint to enable/disable log auto-refresh."""
    logger.debug("Request received for /api/toggle_log_refresh")
    try:
        data = request.get_json()
        if data is None or 'enabled' not in data:
            return jsonify({"error": "Missing 'enabled' field in request body"}), 400

        enabled = bool(data.get('enabled', False))
        state.set_log_auto_refresh(enabled) # Update state
        # No need to restart scheduler here, the job checks the flag

        return jsonify({"success": True, "enabled": enabled})
    except Exception as e:
        logger.exception("Error toggling log refresh state")
        return jsonify({"error": "Failed to toggle log refresh", "detail": str(e)}), 500

# --- Main Execution ---
if __name__ == '__main__':
    # Disable SSL warnings if running against local API with self-signed cert
    is_local_api = "127.0.0.1" in API_BASE_URL or "localhost" in API_BASE_URL
    if is_local_api:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning("SSL certificate verification disabled for API requests (local dev).")
        except ImportError:
            logger.warning("urllib3 not found, cannot disable SSL warnings.")
        except Exception as e:
            logger.warning(f"Could not disable urllib3 warnings: {e}")

    # Start the background scheduler thread
    scheduler_thread = threading.Thread(target=run_scheduler, name="SchedulerThread", daemon=True)
    scheduler_thread.start()

    logger.info(f" --- BrokerDash Pro Starting --- ")
    logger.info(f" Dashboard server running on http://0.0.0.0:{DASHBOARD_PORT}")
    logger.info(f" Connecting to API at: {API_BASE_URL}")
    logger.info(f" API Username: {API_USERNAME}")
    logger.info(f" Using SSL Verification for API: {not is_local_api}")
    logger.info(f" Fetch Intervals: Stats={FETCH_STATS_INTERVAL_SECONDS}s, Queues={FETCH_QUEUES_INTERVAL_SECONDS}s, LogList={FETCH_LOGLIST_INTERVAL_SECONDS}s")
    logger.info(f" Log Auto-Refresh Interval: {FETCH_LOGCONTENT_INTERVAL_SECONDS}s")
    logger.info(f" Max Chart History: {MAX_CHART_HISTORY} points")
    logger.info(f" Log Chunk Size: {LOG_CHUNK_SIZE} lines")
    logger.info(f" ----------------------------- ")

    try:
        # Use Waitress for a more production-ready server than Flask's dev server
        try:
            from waitress import serve
            logger.info("Starting server with Waitress...")
            serve(app, host='0.0.0.0', port=DASHBOARD_PORT, threads=12) # Increased threads
        except ImportError:
            logger.warning("Waitress not found. Falling back to Flask's development server (not recommended for production).")
            app.run(host='0.0.0.0', port=DASHBOARD_PORT, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        logger.info("Dashboard server stopped by user (KeyboardInterrupt).")
    except Exception as e:
        logger.critical(f"Dashboard server failed to start or crashed: {e}", exc_info=True)
        logger.critical("Check configuration, network connectivity, and permissions.")

    logger.info("BrokerDash Pro server exiting.")