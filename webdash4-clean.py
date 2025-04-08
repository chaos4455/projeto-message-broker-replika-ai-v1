# dashboard_server_pro_separated.py
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
import traceback # For detailed error logging

import requests
import schedule
# Use render_template now
from flask import Flask, Response, jsonify, render_template, request
from flask_cors import CORS
# Markup potentially needed if passing pre-formatted HTML snippets in future
# from markupsafe import Markup

# --- Configuration (Same as before) ---
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
FETCH_LOGCONTENT_INTERVAL_SECONDS = 30

MAX_CHART_HISTORY = 360
LOG_CHUNK_SIZE = 250
REQUESTS_TIMEOUT = 15
MAX_LOG_LINES_MEMORY = 5000

# --- Logging (Same as before) ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(threadName)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('BrokerDashPro')
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("schedule").setLevel(logging.WARNING)
logging.getLogger('werkzeug').setLevel(logging.WARNING)

# --- Global State (DashboardState Class - Same as previous version) ---
# --- Global State ---
class DashboardState:
    """Manages the shared state of the dashboard data, ensuring thread safety."""

    def __init__(self, max_history, log_chunk_size):
        """Initializes the dashboard state."""
        self.lock = Lock()  # Thread lock for protecting shared attributes

        # --- Current State Data ---
        self.latest_stats = {}
        self.latest_queues = []
        self.last_api_error = None
        self.last_successful_stats_fetch = None
        self.last_successful_queues_fetch = None
        self.last_successful_loglist_fetch = None
        self.last_successful_logcontent_fetch = None

        # --- Authentication & Timestamps ---
        self.api_access_token = None
        self.login_needed = True
        self.server_start_time = datetime.now(timezone.utc)
        self.last_calc_timestamp = None

        # --- Fetching Flags ---
        self.is_fetching_stats = False
        self.is_fetching_queues = False
        self.is_fetching_loglist = False
        self.is_fetching_logcontent = False

        # --- History Deques ---
        self.max_history = max_history
        self.time_labels = deque(maxlen=max_history)
        self.request_rate_history = deque(maxlen=max_history)      # Rate (events/sec)
        self.processed_rate_history = deque(maxlen=max_history)    # Rate (events/sec)
        self.failed_rate_history = deque(maxlen=max_history)       # Rate (events/sec)
        self.message_status_history = {                            # Absolute counts
            "pending": deque(maxlen=max_history),
            "processing": deque(maxlen=max_history),
            "failed": deque(maxlen=max_history),
            "processed": deque(maxlen=max_history)
        }
        self.performance_history = {                               # Percentages / MB
            "process_cpu": deque(maxlen=max_history),
            "process_memory": deque(maxlen=max_history), # In MB
            "system_cpu": deque(maxlen=max_history),
            "system_memory": deque(maxlen=max_history) # As %
        }
        self.http_error_rate_history = deque(maxlen=max_history)   # Rate (%)

        # --- Rate Calculation State ---
        self.previous_total_requests = 0
        self.previous_total_processed = 0
        self.previous_total_failed = 0
        self.previous_req_by_status = {}

        # --- Log State ---
        self.log_chunk_size = log_chunk_size
        self.available_log_files = []
        self.current_log_filename = None
        self.log_lines = deque(maxlen=MAX_LOG_LINES_MEMORY)        # Holds actual log line data
        self.log_next_fetch_start_line = None                      # For fetching older lines
        self.log_fetch_error = None
        self.log_auto_refresh_enabled = True                       # Default initial state

    # --- Rate Calculation Methods ---

    def _update_rate_history(self, history_deque, current_total, previous_total_attr, interval_seconds):
        """Calculates and appends a rate (events/sec) to a history deque."""
        # This method modifies previous_* attributes, lock is acquired by the caller (update_stats_history)
        current_val = current_total if isinstance(current_total, (int, float)) else 0
        # Use getattr safely with default 0 if attribute doesn't exist yet
        prev_val = getattr(self, previous_total_attr, 0)
        delta = max(0, current_val - prev_val)
        rate = delta / interval_seconds if interval_seconds > 0 else 0
        history_deque.append(round(rate, 2)) # Store rate per second
        # Update the previous total for the next calculation
        setattr(self, previous_total_attr, current_val)

    def _update_http_error_rate(self, current_req_by_status, interval_seconds):
        """Calculates and appends the HTTP error rate (%) to history."""
        # This method modifies previous_req_by_status, lock is acquired by the caller (update_stats_history)
        current_total = 0
        current_errors = 0
        safe_current_req_by_status = {}
        for status, count in current_req_by_status.items():
            try:
                code_str = str(status)
                count_val = int(count)
                safe_current_req_by_status[code_str] = count_val
                current_total += count_val
                # Consider codes 400 and above as errors
                if int(code_str) >= 400:
                    current_errors += count_val
            except (ValueError, TypeError):
                logger.warning(f"Invalid status/count in requests_by_status: {status}={count}")
                continue # Skip invalid entries

        # Use the previously stored counts for comparison
        prev_total = sum(self.previous_req_by_status.values())
        prev_errors = sum(count for status, count in self.previous_req_by_status.items() if int(status) >= 400)

        delta_total = max(0, current_total - prev_total)
        delta_errors = max(0, current_errors - prev_errors)

        # Calculate rate as percentage over the interval
        rate = (delta_errors / delta_total * 100) if delta_total > 0 else 0
        self.http_error_rate_history.append(round(rate, 2))
        # Store the cleaned dictionary for the next calculation
        self.previous_req_by_status = safe_current_req_by_status

    # --- State Update Methods ---

    def update_stats_history(self, stats):
        """Updates all history deques based on new stats data."""
        # This method modifies multiple shared attributes, acquire lock once.
        with self.lock:
            now = datetime.now(timezone.utc)
            now_label = now.strftime("%H:%M:%S")

            # Calculate actual interval for rate calculation
            interval = 0
            if self.last_calc_timestamp:
                interval = (now - self.last_calc_timestamp).total_seconds()
            self.last_calc_timestamp = now # Update timestamp regardless of interval

            # Only add history if interval is reasonable (avoid division by zero or spikes)
            if interval > 0.1:
                self.time_labels.append(now_label)

                # Calculate rates (events/sec) - Pass interval to helpers
                self._update_rate_history(self.request_rate_history, stats.get("requests_total"), "previous_total_requests", interval)
                self._update_rate_history(self.processed_rate_history, stats.get("messages_processed"), "previous_total_processed", interval)
                self._update_rate_history(self.failed_rate_history, stats.get("messages_failed"), "previous_total_failed", interval)

                # HTTP Error Rate (%)
                self._update_http_error_rate(stats.get("requests_by_status", {}), interval)

                # Message Counts (absolute values)
                for status in ["pending", "processing", "failed", "processed"]:
                    # Ensure default 0 if key is missing
                    self.message_status_history[status].append(stats.get(f"messages_{status}", 0))

                # Performance Metrics (% or MB)
                sys_stats = stats.get("system", {}) # Use empty dict if 'system' key is missing
                self.performance_history["process_cpu"].append(round(safe_float(sys_stats.get("process_cpu_percent")), 2))
                self.performance_history["process_memory"].append(round(safe_float(sys_stats.get("process_memory_mb")), 2)) # Keep as MB
                self.performance_history["system_cpu"].append(round(safe_float(sys_stats.get("cpu_percent")), 2))
                self.performance_history["system_memory"].append(round(safe_float(sys_stats.get("memory_percent")), 2)) # As %
            else:
                logger.debug(f"Skipping history update due to small interval: {interval:.3f}s")


    def update_error(self, error_message, error_type="generic"):
        """Sets the last API error message and type."""
        # Modifies last_api_error
        with self.lock:
            timestamp = datetime.now(timezone.utc).isoformat()
            self.last_api_error = {"message": str(error_message), "type": error_type, "timestamp": timestamp}
            logger.error(f"API Error Recorded ({error_type}): {error_message}")

    def clear_error(self, error_type="generic"):
        """Clears the last API error if it matches the specified type."""
        # Modifies last_api_error
        with self.lock:
            # Clear only if the *current* error matches the type being cleared
            if self.last_api_error and self.last_api_error.get("type") == error_type:
                cleared_message = self.last_api_error.get("message", "")[:50] # Log snippet
                self.last_api_error = None
                logger.info(f"Cleared API error (type: {error_type}, msg: '{cleared_message}...').")

    def update_log_lines(self, new_lines, is_prepend=False, next_start_for_older=None):
        """Updates log lines deque, handling duplicates and direction."""
        # Modifies log_lines, log_fetch_error, last_successful_logcontent_fetch, log_next_fetch_start_line
        with self.lock:
            # Clear previous error on successful fetch *before* processing lines
            self.log_fetch_error = None
            self.last_successful_logcontent_fetch = datetime.now(timezone.utc).isoformat()
            # Update the pointer for where the *next* older fetch should begin
            self.log_next_fetch_start_line = next_start_for_older

            if not isinstance(new_lines, list):
                logger.warning("update_log_lines received non-list input. Ignoring.")
                return

            processed_count = 0
            added_hashes = set() # Track hashes added in this batch

            if is_prepend: # Fetching older logs, append to the *end* of our deque
                # Check against existing hashes in the deque to avoid duplicates from overlapping fetches
                # This check isn't perfect but helps prevent obvious duplication.
                existing_hashes = set(hash(f"{l.get('timestamp')}_{l.get('message')}") for l in self.log_lines)
                for line in new_lines: # Assume API returns older lines first in the list
                    line_hash = hash(f"{line.get('timestamp')}_{line.get('message')}")
                    if line_hash not in existing_hashes and line_hash not in added_hashes:
                        self.log_lines.append(line) # Append older lines
                        added_hashes.add(line_hash)
                        processed_count += 1
                if processed_count > 0:
                    logger.debug(f"Appended {processed_count}/{len(new_lines)} older unique log lines.")

            else: # Fetching latest logs, prepend to the *start* of our deque
                # Check against recent lines already in the deque
                existing_recent_hashes = set(hash(f"{l.get('timestamp')}_{l.get('message')}") for l in list(self.log_lines)[:LOG_CHUNK_SIZE*2])
                unique_lines_to_add = []

                for line in new_lines: # Assume API returns newest lines first (e.g., from tail)
                    line_hash = hash(f"{line.get('timestamp')}_{line.get('message')}")
                    if line_hash not in existing_recent_hashes and line_hash not in added_hashes:
                        unique_lines_to_add.append(line)
                        added_hashes.add(line_hash) # Add new one to check against incoming batch

                # Prepend unique new lines, maintaining their received order (newest first)
                for line in reversed(unique_lines_to_add):
                      self.log_lines.appendleft(line) # Prepend newer lines
                      processed_count += 1
                if processed_count > 0:
                    logger.debug(f"Prepended {processed_count}/{len(unique_lines_to_add)} new unique log lines.")

            # Max line limit (MAX_LOG_LINES_MEMORY) is handled automatically by deque's maxlen

    def set_log_auto_refresh(self, enabled: bool):
        """Sets the log auto-refresh flag."""
        # Modifies log_auto_refresh_enabled
        with self.lock:
            if self.log_auto_refresh_enabled != enabled:
                self.log_auto_refresh_enabled = enabled
                logger.info(f"Log auto-refresh explicitly set to: {enabled}")

    # --- Authentication Methods ---

    def needs_login(self):
        """Checks if an API login is currently required."""
        # Reads login_needed, api_access_token
        with self.lock:
            return self.login_needed or not self.api_access_token

    def get_token(self):
        """Returns the current API access token."""
        # Reads api_access_token
        with self.lock:
            return self.api_access_token

    def set_token(self, token):
        """Sets the API access token and updates login status."""
        # Modifies api_access_token, login_needed, last_api_error
        with self.lock:
            self.api_access_token = token
            self.login_needed = False
            # Clear any outstanding auth errors on successful token set
            if self.last_api_error and self.last_api_error.get("type") == "auth":
                 self.last_api_error = None
                 logger.info("Cleared previous auth error on successful token set.")
            logger.info("API access token set successfully.")

    def invalidate_token(self, reason="Authentication failed"):
        """Invalidates the current token and forces login."""
        # Modifies api_access_token, login_needed, last_api_error
        with self.lock:
            token_was_present = bool(self.api_access_token)
            self.api_access_token = None
            self.login_needed = True
            # Record the reason as an auth error
            timestamp = datetime.now(timezone.utc).isoformat()
            self.last_api_error = {"message": str(reason), "type": "auth", "timestamp": timestamp}
            if token_was_present:
                logger.warning(f"API token invalidated: {reason}")
            else:
                logger.info(f"Setting login needed state: {reason}")


    # --- Data Retrieval Methods for API ---

    def get_snapshot_for_dashboard(self):
        """Returns a snapshot of the current state for the dashboard API."""
        # Reads multiple attributes, returns copies for safety
        with self.lock:
            # Create copies of mutable objects (dicts, lists, deques)
            history_copy = {
                "time_labels": list(self.time_labels),
                "request_rate_history": list(self.request_rate_history),
                "processed_rate_history": list(self.processed_rate_history),
                "failed_rate_history": list(self.failed_rate_history),
                "message_status": {k: list(v) for k, v in self.message_status_history.items()},
                "performance": {k: list(v) for k, v in self.performance_history.items()},
                "http_error_rate_history": list(self.http_error_rate_history)
            }
            return {
                "latest_stats": self.latest_stats.copy(),
                "latest_queues": self.latest_queues[:], # Shallow copy of list
                "history": history_copy,
                "current_log_filename": self.current_log_filename,
                "log_fetch_error": self.log_fetch_error,
                "last_successful_stats_fetch": self.last_successful_stats_fetch,
                "last_successful_queues_fetch": self.last_successful_queues_fetch,
                # Copy the error dict if it exists
                "last_api_error": self.last_api_error.copy() if self.last_api_error else None,
                "log_auto_refresh_enabled": self.log_auto_refresh_enabled,
                "available_log_files": self.available_log_files[:], # Shallow copy of list
                "log_next_fetch_start_line": self.log_next_fetch_start_line,
                "server_start_time": self.server_start_time.isoformat()
            }

    def get_log_data_for_request(self):
         """Returns the current log data state for the log API."""
         # Reads log-related attributes
         with self.lock:
             return {
                 "filename": self.current_log_filename,
                 "lines": list(self.log_lines), # Return current buffer as a list copy
                 "next_fetch_start_line": self.log_next_fetch_start_line,
                 "log_fetch_error": self.log_fetch_error,
                 "last_successful_logcontent_fetch": self.last_successful_logcontent_fetch,
                 "log_auto_refresh_enabled": self.log_auto_refresh_enabled
             }

# --- Initialize Global State ---
# state = DashboardState(MAX_CHART_HISTORY, LOG_CHUNK_SIZE) # This line remains outside the class


# Initialize Global State
state = DashboardState(MAX_CHART_HISTORY, LOG_CHUNK_SIZE)

# --- Utilities ---

def safe_float(value, default=0.0):
    """
    Safely attempts to convert a value to a float.

    Args:
        value: The value to convert.
        default: The value to return if conversion fails or value is None.

    Returns:
        The float representation of the value, or the default value.
    """
    if value is None:
        return default
    try:
        # Attempt conversion
        return float(value)
    except (ValueError, TypeError):
        # Handle cases where conversion isn't possible (e.g., invalid string)
        # Optionally log the error here if needed for debugging:
        # logger.debug(f"Failed to convert value '{value}' to float.", exc_info=True)
        return default

def format_timedelta_human(seconds):
    """Converts seconds into a human-readable string like 1d 2h 3m 4s."""
    if seconds is None or not isinstance(seconds, (int, float)) or seconds < 0:
        return "--"
    seconds = int(seconds)
    if seconds < 1:
        return "< 1 sec"

    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)

    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    # Show seconds if they exist OR if no other parts were added (e.g., for 0 seconds)
    if secs > 0 or not parts:
        parts.append(f"{secs}s")

    return " ".join(parts)

def bytes_to_human(n_bytes, precision=1):
    """Converts bytes to a human-readable string (KB, MB, GB...)."""
    if n_bytes is None or not isinstance(n_bytes, (int, float)) or n_bytes < 0:
        return "--"
    try:
        # Ensure n_bytes is an integer for calculations
        n_bytes = int(n_bytes)
    except (ValueError, TypeError):
        return "--" # Cannot convert input to int

    if n_bytes == 0:
        return "0 B"

    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    # Calculate power safely, handle log(0) case implicitly by n_bytes > 0 check
    power = min(int(math.log(n_bytes, 1024)), len(units) - 1) if n_bytes > 0 else 0

    try:
        value = n_bytes / (1024 ** power)
        # Format the value with specified precision
        return f"{value:.{precision}f} {units[power]}"
    except ZeroDivisionError:
        # Should not happen with the power calculation logic, but handle defensively
        return f"{n_bytes} B"
    except Exception:
        # Catch any unexpected formatting errors
        logger.warning(f"Error formatting bytes: {n_bytes}", exc_info=True)
        return "--"

# --- API Error Handling Decorator (handle_api_errors - Same as previous version) ---
# --- API Error Handling Decorator ---
def handle_api_errors(error_scope="generic"):
    """
    Decorator to handle common API request errors, including authentication.

    Args:
        error_scope (str): A label for the type of operation (e.g., "stats", "logs")
                           used for targeted error clearing.

    Returns:
        A decorator function.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            global state
            token = None # Initialize token variable

            # --- Authentication Check ---
            if state.needs_login():
                logger.info(f"Login required for {func.__name__}, attempting...")
                if not login_to_api():
                    # --- Login failed ---
                    logger.error(f"Aborting {func.__name__}: API login failed.")
                    # Ensure an appropriate 'auth' error is set in the state
                    # Only update if no error exists or the existing one isn't 'auth'
                    with state.lock: # Acquire lock to safely check/update error state
                        if not state.last_api_error or state.last_api_error.get("type") != "auth":
                            state.update_error("API login failed or credentials incorrect.", "auth")
                            # Note: update_error already logs the error
                    return False # Indicate failure of the decorated function call

                # --- Login successful, get token ---
                token = state.get_token()
                if not token:
                    # This should ideally not happen if login_to_api works correctly
                    logger.error(f"Internal dashboard error: Token missing after successful login attempt for {func.__name__}.")
                    state.update_error("Internal error: Token lost after login.", "internal")
                    return False
            else:
                # --- Already logged in (or token exists), get token ---
                token = state.get_token()
                if not token:
                     # If token is somehow None even when login wasn't needed, flag it.
                     logger.error(f"Internal dashboard error: Token is unexpectedly None for {func.__name__} despite not needing login.")
                     state.update_error("Internal error: Token unexpectedly missing.", "internal")
                     state.invalidate_token("Token missing unexpectedly") # Force re-login next time
                     return False

            # --- Prepare Request ---
            headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/json'}
            # Disable SSL verification only for local addresses
            is_local_api = "127.0.0.1" in API_BASE_URL or "localhost" in API_BASE_URL
            verify_ssl = not is_local_api

            # --- Execute API Call ---
            try:
                # Inject headers and verify_ssl into the decorated function's kwargs
                # This assumes the decorated functions are designed to accept these kwargs
                # or they are handled appropriately within the function call itself.
                # A safer way might be to pass them explicitly if the function signature allows.
                # For now, keeping original logic:
                kwargs['headers'] = headers
                kwargs['verify_ssl'] = verify_ssl
                result = func(*args, **kwargs)

                # If the function executed and didn't raise an exception that implies success
                # Clear the specific error scope *if* the result indicates success (e.g., returns True or data)
                # Check against explicit False return, as func might return None or data on success.
                if result is not False:
                     state.clear_error(error_scope)
                return result # Pass back the result (could be data, True, False, None)

            # --- Exception Handling ---
            except requests.exceptions.Timeout as e:
                err_msg = f"API timeout calling {func.__name__}"
                state.update_error(err_msg, error_scope)
                logger.warning(f"{err_msg}: {e}")
            except requests.exceptions.SSLError as e:
                err_msg = f"API SSL Error in {func.__name__}"
                state.update_error(f"{err_msg}: {e}. Check certs/URL.", error_scope)
                logger.error(f"{err_msg}: {e}")
            except requests.exceptions.ConnectionError as e:
                err_msg = f"API Connection Error in {func.__name__}"
                state.update_error(f"{err_msg}: {e}. Cannot reach {API_BASE_URL}", error_scope)
                logger.error(f"{err_msg}: {e}")
            except requests.exceptions.HTTPError as e:
                status_code = getattr(e.response, 'status_code', 'N/A')
                response_text = ""
                try:
                    response_text = e.response.text[:200] if e.response is not None else "N/A"
                except Exception:
                    pass # Ignore errors trying to get response text
                error_detail = f"API HTTP Error ({status_code}) in {func.__name__}: {e}. Response snippet: {response_text}"

                if status_code in [401, 403]:
                    logger.warning(f"API auth error ({status_code}) calling {func.__name__}. Invalidating token.")
                    # Invalidate token with a specific reason related to the call
                    state.invalidate_token(f"API Auth error ({status_code}) calling {func.__name__}")
                else:
                    # Log other HTTP errors without invalidating token immediately
                    state.update_error(error_detail, error_scope)
                    logger.warning(error_detail) # Log as warning, might be transient
            except requests.exceptions.RequestException as e:
                # Catch broader request exceptions (e.g., DNS errors, invalid URL)
                err_msg = f"General API Request Failed in {func.__name__}"
                state.update_error(f"{err_msg}: {e}", error_scope)
                logger.error(f"{err_msg}: {e}")
            except json.JSONDecodeError as e:
                # Catch errors parsing the JSON response
                err_msg = f"API response is not valid JSON in {func.__name__}"
                state.update_error(f"{err_msg}. Error: {e}", error_scope)
                logger.error(f"{err_msg}: {e}")
            except Exception as e:
                # Catch any other unexpected errors
                logger.exception(f"Unexpected error during API call in {func.__name__}") # Log full traceback
                state.update_error(f"Unexpected error in {func.__name__}: {type(e).__name__} - {e}", "internal")

            # If any exception occurred, return False to signal failure
            return False
        return wrapper
    return decorator

# --- API Interaction (login_to_api, fetch_stats_data, fetch_queues_data, fetch_log_list, fetch_log_content - Same as previous version) ---
# ... (API functions omitted for brevity, assume they are here unchanged) ...
def login_to_api():
    global state; logger.info(f"Attempting login to {API_LOGIN_URL}..."); verify_ssl = not ("127.0.0.1" in API_BASE_URL or "localhost" in API_BASE_URL); login_success = False
    try:
        response = requests.post( API_LOGIN_URL, data={'username': API_USERNAME, 'password': API_PASSWORD}, verify=verify_ssl, timeout=REQUESTS_TIMEOUT ); response.raise_for_status(); token_data = response.json()
        if "access_token" in token_data: state.set_token(token_data["access_token"]); login_success = True
        else: logger.error("Login response missing 'access_token'."); state.update_error("Login response missing 'access_token'", "auth")
    except requests.exceptions.HTTPError as e:
         status_code = getattr(e.response, 'status_code', 'N/A'); detail = f"Status: {status_code}";
         try:
             if e.response is not None: detail += f" - {e.response.json().get('detail', e.response.text[:100])}"
         except Exception: pass; logger.error(f"API login HTTP error ({detail}): {e}"); state.update_error(f"API login failed ({detail})", "auth")
    except requests.exceptions.RequestException as e: logger.error(f"API login request failed: {e}"); state.update_error(f"API login failed: {e}", "auth")
    except json.JSONDecodeError as e: logger.error(f"Failed to decode login response: {e}"); state.update_error("Invalid JSON during login", "auth")
    except Exception as e: logger.exception("Unexpected error during login"); state.update_error(f"Unexpected login error: {e}", "internal")
    if not login_success: state.invalidate_token("Login attempt failed")
    return login_success

@handle_api_errors(error_scope="stats")
def fetch_stats_data(*args, **kwargs): # Accept args/kwargs from decorator
    """
    Fetches stats data from the API.
    Uses @handle_api_errors for auth, error handling, headers, and SSL verification.
    """
    global state

    # Check and set fetching flag atomically using the lock
    with state.lock:
        if state.is_fetching_stats:
            logger.debug("Stats fetch skipped, already in progress.")
            return True # Indicate not an error, just busy
        # Mark as fetching *inside* the lock to prevent race condition
        state.is_fetching_stats = True
        logger.debug("Marked is_fetching_stats = True")

    logger.debug("Fetching stats data...")
    success = False # Assume failure until proven otherwise

    # Retrieve headers and verify_ssl passed by the decorator from kwargs
    # These are added by the handle_api_errors decorator
    headers = kwargs.get('headers')
    verify_ssl = kwargs.get('verify_ssl')

    if not headers:
        logger.error("Internal error: Headers not found in kwargs for fetch_stats_data. Decorator might be misconfigured.")
        # Reset flag since we can't proceed
        with state.lock:
            state.is_fetching_stats = False
        return False # Cannot proceed without headers

    try:
        response = requests.get(
            API_STATS_URL,
            headers=headers,
            verify=verify_ssl,
            timeout=REQUESTS_TIMEOUT
        )
        response.raise_for_status() # Raise HTTPError for bad status codes (4xx or 5xx)
        stats = response.json()

        # --- Data Validation ---
        # Check if the received data is a non-empty dictionary
        if not isinstance(stats, dict) or not stats:
            logger.warning("Received empty or invalid stats data structure from API.")
            # Set an error state. The request succeeded (2xx), but data is bad.
            # Don't mark as 'success = True'.
            state.update_error("Received empty/invalid stats data", "stats")
            # Let the function return the current 'success' value (which is False)
        else:
            # --- Data Processing & State Update ---
            # Acquire lock again for the compound update operation
            with state.lock:
                state.latest_stats = stats
                state.last_successful_stats_fetch = datetime.now(timezone.utc).isoformat()
                # Update history *after* successful fetch and storing latest_stats
                state.update_stats_history(stats) # Assumes this method is thread-safe or called under lock
            logger.info(f"Stats data updated successfully at {state.last_successful_stats_fetch}")
            success = True # Mark as successful only after processing valid data

    # Exceptions during the requests.get call (Timeout, ConnectionError, HTTPError, etc.)
    # are caught and handled by the @handle_api_errors decorator.
    # The decorator will update the error state and return False in those cases.

    finally:
        # CRITICAL: Ensure the fetching flag is ALWAYS reset, even if errors occurred
        # during the try block *before* the decorator caught them (e.g., JSONDecodeError handled here, though decorator catches it too),
        # or if data validation failed above.
        # --- Correct Indentation Here ---
        with state.lock: # Acquire lock to safely reset the flag
            state.is_fetching_stats = False
            logger.debug("Reset is_fetching_stats flag.")

    # Return the success status based ONLY on whether valid data was processed in *this* function.
    # The decorator overrides this to False if it catches request-level exceptions.
    return success

@handle_api_errors(error_scope="queues")
def fetch_queues_data(*args, **kwargs): # Accept args/kwargs from decorator
    """
    Fetches queue data from the API.
    Uses @handle_api_errors for auth, error handling, headers, and SSL verification.
    """
    global state

    # Check and set fetching flag atomically
    with state.lock:
         if state.is_fetching_queues:
             logger.debug("Queues fetch skipped, already in progress.")
             return True # Not an error, just busy
         # Mark as fetching inside the lock
         state.is_fetching_queues = True
         logger.debug("Marked is_fetching_queues = True")

    logger.debug("Fetching queues data...")
    success = False # Assume failure

    # Retrieve headers and verify_ssl passed by the decorator
    headers = kwargs.get('headers')
    verify_ssl = kwargs.get('verify_ssl')

    if not headers:
        logger.error("Internal error: Headers not found in kwargs for fetch_queues_data.")
        # Reset flag since we can't proceed
        with state.lock:
            state.is_fetching_queues = False
        return False

    try:
        response = requests.get(
            API_QUEUES_URL,
            headers=headers,
            verify=verify_ssl,
            timeout=REQUESTS_TIMEOUT
        )
        response.raise_for_status() # Raise HTTPError for bad status codes
        queues = response.json()

        # --- Data Validation ---
        # Expecting a list of queue objects
        if not isinstance(queues, list):
            logger.warning("Received non-list data structure for queues from API.")
            # Set error state for bad data, but don't mark as success
            state.update_error("Received invalid queues data format", "queues")
            # Let function return current 'success' value (False)
        else:
            # --- Data Processing & State Update ---
            # Acquire lock again for state update
            with state.lock:
                # Sort queues alphabetically by name for consistent display
                state.latest_queues = sorted(queues, key=lambda q: q.get('name', ''))
                state.last_successful_queues_fetch = datetime.now(timezone.utc).isoformat()
            logger.info(f"Queues data updated successfully at {state.last_successful_queues_fetch} ({len(queues)} queues)")
            success = True # Mark as successful only after processing valid data

    # Request-level exceptions handled by @handle_api_errors decorator

    finally:
        # CRITICAL: Always reset the fetching flag
        # --- Correct Indentation Here ---
        with state.lock: # Acquire lock to safely reset the flag
            state.is_fetching_queues = False
            logger.debug("Reset is_fetching_queues flag.")

    # Return success status based on processing valid data in *this* function.
    # Decorator returns False on request exceptions.
    return success

@handle_api_errors(error_scope="loglist")
def fetch_log_list(*args, **kwargs): # Accept args/kwargs from decorator
    """
    Fetches the list of available log files from the API.
    Uses @handle_api_errors for auth, error handling, headers, and SSL verification.
    Also handles selecting the newest log if none is currently selected.
    """
    global state

    # Check and set fetching flag atomically
    with state.lock:
        if state.is_fetching_loglist:
            logger.debug("Log list fetch skipped, already in progress.")
            return True # Not an error, just busy
        state.is_fetching_loglist = True
        logger.debug("Marked is_fetching_loglist = True")

    logger.debug("Fetching log file list...")
    success = False # Assume failure

    # Retrieve headers and verify_ssl passed by the decorator
    headers = kwargs.get('headers')
    verify_ssl = kwargs.get('verify_ssl')

    if not headers:
        logger.error("Internal error: Headers not found in kwargs for fetch_log_list.")
        # Reset flag since we can't proceed
        with state.lock:
            state.is_fetching_loglist = False
        return False

    try:
        response = requests.get(
            API_LOGS_LIST_URL,
            headers=headers,
            verify=verify_ssl,
            timeout=REQUESTS_TIMEOUT
        )
        response.raise_for_status() # Raise HTTPError for bad status codes
        log_data = response.json()

        # --- Data Validation ---
        # Expecting a dictionary like: {"log_files": ["file1.log", "file2.log"]}
        if not isinstance(log_data, dict) or \
           "log_files" not in log_data or \
           not isinstance(log_data["log_files"], list):
            logger.warning("Received invalid log list data structure from API.")
            state.update_error("Invalid log list format from API", "loglist")
            # Let function return current 'success' value (False)
        else:
            # --- Data Processing & State Update ---
            files = sorted(log_data["log_files"], reverse=True) # Assume newest first is desirable

            # Acquire lock for compound state updates related to log files
            with state.lock:
                state.available_log_files = files
                state.last_successful_loglist_fetch = datetime.now(timezone.utc).isoformat()
                logger.info(f"Log list updated at {state.last_successful_loglist_fetch}: {len(files)} files.")

                # --- Handle Current Log File ---
                current_file = state.current_log_filename
                file_disappeared = current_file and current_file not in files
                no_file_selected = not current_file and files

                if file_disappeared:
                    logger.warning(f"Current log file '{current_file}' no longer available in list. Clearing view.")
                    state.current_log_filename = None
                    state.log_lines.clear()
                    state.log_next_fetch_start_line = None
                    # Set a specific error message for the log viewer
                    state.log_fetch_error = "Current log file disappeared or was rotated."

                elif no_file_selected:
                    # If no log file is selected and logs ARE available, select the newest one
                    newest_log = files[0]
                    logger.info(f"No log selected, automatically selecting newest: '{newest_log}'")
                    state.current_log_filename = newest_log
                    state.log_lines.clear() # Clear old lines from previous file if any
                    state.log_next_fetch_start_line = None # Reset pagination
                    state.log_fetch_error = None # Clear previous log-specific errors
                    # Trigger an initial content fetch shortly after selecting the new file
                    # Cancel any previous pending initial fetch first
                    schedule.clear('initial-log-content')
                    # Schedule the job to run once, very soon
                    schedule.every(1).second.do(fetch_log_content_job, fetch_older=False).tag('initial-log-content')
                    logger.debug("Scheduled initial log content fetch for the newly selected file.")

            # Mark as successful only after processing valid data
            success = True

    # Request-level exceptions handled by @handle_api_errors decorator

    finally:
        # CRITICAL: Always reset the fetching flag
        # --- Correct Indentation Here ---
        with state.lock: # Acquire lock to safely reset the flag
            state.is_fetching_loglist = False
            logger.debug("Reset is_fetching_loglist flag.")

    # Return success status based on processing valid data in *this* function.
    # Decorator returns False on request exceptions.
    return success

@handle_api_errors(error_scope="logcontent")
def fetch_log_content(filename, fetch_older=False, headers=None, verify_ssl=None, **decorator_kwargs): # Accept potential other kwargs
    """
    Fetches log content chunks from the API. Handles fetching newer or older lines.
    Uses @handle_api_errors for auth, basic error handling.
    Assumes headers and verify_ssl are passed by the decorator.
    """
    global state

    # Check if filename is provided
    if not filename:
        logger.warning("fetch_log_content skipped: no filename provided.")
        return False # Indicate skipped due to missing filename

    # Retrieve headers and verify_ssl passed by the decorator from its kwargs
    # The decorator adds these to the function's actual call arguments.
    # Check if they were passed directly or via decorator_kwargs if the signature was *args, **kwargs
    if headers is None:
        headers = decorator_kwargs.get('headers')
    if verify_ssl is None:
        verify_ssl = decorator_kwargs.get('verify_ssl')

    if not headers:
        logger.error("Internal error: Headers not found for fetch_log_content.")
        # Cannot proceed without headers, but don't set fetching flag yet
        return False

    # Check and set fetching flag, prepare parameters atomically
    params = {} # Initialize params
    start_line_for_older_request = None
    should_proceed = False # Flag to determine if we actually make the request

    with state.lock:
        if state.is_fetching_logcontent:
            logger.debug(f"Log fetch '{filename}' skipped, already in progress.")
            return True # Not an error, just busy

        # Determine parameters based on fetch_older flag
        if fetch_older:
            older_start_num = state.log_next_fetch_start_line
            if older_start_num and older_start_num > 0:
                # --- Corrected Parameter Logic for Older Logs ---
                params['start'] = older_start_num
                # Calculate end based on start and chunk size
                params['end'] = older_start_num + state.log_chunk_size - 1
                # No need for 'limit' or 'tail' when using start/end
                start_line_for_older_request = older_start_num
                logger.debug(f"Configured Fetch older '{filename}' from line {older_start_num} to {params['end']}")
                should_proceed = True
            else:
                # No valid starting point for older logs
                logger.info(f"Fetch older '{filename}' skipped: No valid next_start_line ({state.log_next_fetch_start_line}).")
                # No need to set is_fetching_logcontent = True if we don't proceed
                return True # Not an error, just nothing older to fetch
        else:
            # --- Corrected Parameter Logic for Latest Logs ---
            # Prefer 'tail' if API supports it, otherwise maybe 'limit' or default behavior
            # Assuming API prefers 'tail'
            params['tail'] = state.log_chunk_size
            # Remove 'limit' if 'tail' is used, avoid conflicting params
            # if 'limit' in params: del params['limit'] # Remove this if limit was default elsewhere
            logger.debug(f"Configured Fetch latest '{filename}' using tail={state.log_chunk_size}.")
            should_proceed = True

        # If we determined we should make a request, set the flag and clear errors
        if should_proceed:
            state.is_fetching_logcontent = True
            state.log_fetch_error = None # Clear previous fetch error before attempting
            logger.debug("Marked is_fetching_logcontent = True")
        else:
            # If for some reason should_proceed is false here (shouldn't happen with current logic)
             return True # Exit gracefully

    # --- Perform API Request (only if should_proceed was True) ---
    logger.info(f"Fetching log content from API for '{filename}' with params: {params}")
    success = False
    try:
        # Construct URL: Ensure filename is URL-encoded
        # Simple encoding for basic cases. Use urllib.parse.quote for robustness if needed.
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
            # Set success = False (already default), let finally block reset flag
        else:
            logger.debug(f"Received {len(log_lines_received)} log lines for '{filename}'.")

            # --- Process received lines & Determine Next Older Start Line ---
            # Acquire lock for state updates
            with state.lock:
                next_start_line_calc = None # Default to None (no more older known)

                if fetch_older and start_line_for_older_request:
                    # If we received lines for an 'older' request:
                    # If we got a full chunk, assume more older logs exist *before* this chunk.
                    # The *next* older request should start *after* this current block.
                    if len(log_lines_received) >= state.log_chunk_size:
                        next_start_line_calc = start_line_for_older_request + state.log_chunk_size
                    # Otherwise (received less than full chunk), assume we hit the beginning.
                    # next_start_line_calc remains None.

                elif not fetch_older:
                    # Fetching latest ('tail'): Determine if older logs *might* exist *before* this chunk.
                    # This is heuristic. If we received a full chunk, enable "Load Older".
                    if len(log_lines_received) >= state.log_chunk_size:
                        # The next older request conceptually starts *after* this 'tail' chunk ends.
                        # In line numbering, if tail=250 got lines 0-249 (hypothetical perfect numbering),
                        # the next older block would start at line 250.
                        next_start_line_calc = state.log_chunk_size + 1 # Enable "Load Older"
                    elif state.log_next_fetch_start_line is None and len(state.log_lines) < state.log_chunk_size:
                        # If it's the very first fetch (no next_start set) and got less than a chunk,
                        # disable "Load Older".
                        next_start_line_calc = None
                    else:
                        # Otherwise (e.g., refreshing latest when older logs already loaded),
                        # *keep* the existing next_start_line pointer.
                        next_start_line_calc = state.log_next_fetch_start_line

                # Update the log lines deque and the pointer for the *next* older fetch
                state.update_log_lines(
                    new_lines=log_lines_received,
                    is_prepend=fetch_older, # True = Append older logs to deque end
                    next_start_for_older=next_start_line_calc
                )
            success = True # Mark success only after valid processing

    # --- Specific Exception Handling (within the function) ---
    except requests.exceptions.HTTPError as e:
        # Handle 404 specifically for logs
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
            # Return False here as the specific fetch failed logically, even if decorator handles general HTTPError
            success = False
        else:
            # Re-raise other HTTP errors to be caught by the decorator
            logger.error(f"Non-404 HTTPError fetching log content for {filename}: {e}")
            raise e # Let decorator handle reporting and return False

    # Other exceptions (Timeout, ConnectionError, JSONDecodeError, RequestException, general Exception)
    # are handled by the @handle_api_errors decorator, which will return False.

    finally:
        # CRITICAL: Ensure the flag is always reset, regardless of success/failure/exception
        # --- Correct Indentation Here ---
        with state.lock: # Acquire lock to safely reset the flag
            state.is_fetching_logcontent = False
            logger.debug("Reset is_fetching_logcontent flag.")

    # Return True only if the fetch+processing inside *this* function was successful.
    # The decorator might still return False if it caught an earlier exception.
    return success

# --- Scheduler Jobs (fetch_stats_job, fetch_queues_job, fetch_loglist_job, fetch_log_content_job, run_scheduler - Same as previous version) ---
# ... (Scheduler functions omitted for brevity, assume they are here unchanged) ...
def fetch_stats_job(): logger.debug("Sched: fetch_stats"); fetch_stats_data()
def fetch_queues_job(): logger.debug("Sched: fetch_queues"); fetch_queues_data()
def fetch_loglist_job(): logger.debug("Sched: fetch_loglist"); fetch_log_list()
def fetch_log_content_job(fetch_older=False):
    global state
    with state.lock: filename = state.current_log_filename; auto_refresh = state.log_auto_refresh_enabled; is_fetching = state.is_fetching_logcontent
    should_fetch = filename and (fetch_older or auto_refresh) and not is_fetching
    if should_fetch: logger.debug(f"Sched: fetch_log_content '{filename}', older={fetch_older}."); fetch_log_content(filename, fetch_older=fetch_older)
    elif not filename: logger.debug("Sched: skip log content (no file).")
    elif not auto_refresh and not fetch_older: logger.debug("Sched: skip log content (auto-refresh off).")
    elif is_fetching: logger.debug(f"Sched: skip log content '{filename}' (busy).")
    # Clear one-time job
    jobs_to_cancel = [j for j in schedule.get_jobs() if 'initial-log-content' in j.tags]
    if jobs_to_cancel:
        for job in jobs_to_cancel: schedule.cancel_job(job); logger.debug(f"Cancelled job: {job}")
    return None

def run_scheduler():
    logger.info("Scheduler thread started."); logger.info("Performing initial data fetch...")
    try: fetch_stats_job(); fetch_queues_job(); fetch_loglist_job()
    except Exception as e: logger.exception("Error during initial data fetch.")
    logger.info("Initial data fetch sequence complete.")
    schedule.every(FETCH_STATS_INTERVAL_SECONDS).seconds.do(fetch_stats_job).tag('stats', 'data')
    schedule.every(FETCH_QUEUES_INTERVAL_SECONDS).seconds.do(fetch_queues_job).tag('queues', 'data')
    schedule.every(FETCH_LOGLIST_INTERVAL_SECONDS).seconds.do(fetch_loglist_job).tag('loglist', 'logs')
    schedule.every(FETCH_LOGCONTENT_INTERVAL_SECONDS).seconds.do(fetch_log_content_job, fetch_older=False).tag('logcontent-auto', 'logs')
    logger.info(f"Scheduled jobs running.")
    while True:
        try: schedule.run_pending()
        except Exception as e: logger.error(f"Error in scheduler loop: {e}", exc_info=True)
        time.sleep(0.5)


# --- Flask App Initialization ---
# *** Specify the template folder ***
app = Flask(__name__, template_folder='dash-templates')
app.logger.handlers = logger.handlers
app.logger.setLevel(logger.level)
CORS(app)


# --- Flask Routes ---
@app.route('/')
def serve_dashboard():
    """Serves the main dashboard HTML page from the template file."""
    logger.info(f"Request for dashboard page from {request.remote_addr}")
    try:
        # Prepare configuration dictionary for JavaScript
        dashboard_config = {
            "API_DASHBOARD_DATA_URL": "/api/dashboard_data",
            "API_LOG_DATA_URL": "/api/log_data",
            "API_FETCH_OLDER_LOGS_URL": "/api/fetch_older_logs",
            "API_TOGGLE_LOG_REFRESH_URL": "/api/toggle_log_refresh",
            "POLLING_INTERVAL_MS": FETCH_STATS_INTERVAL_SECONDS * 1000,
            "LOG_REFRESH_INTERVAL_MS": FETCH_LOGCONTENT_INTERVAL_SECONDS * 1000,
            "MAX_CHART_HISTORY": MAX_CHART_HISTORY,
            "LOG_CHUNK_SIZE": LOG_CHUNK_SIZE,
            "FETCH_STATS_INTERVAL_SECONDS": FETCH_STATS_INTERVAL_SECONDS,
            # Pass initial state needed by JS
            "LOG_AUTO_REFRESH_ENABLED_INIT": state.log_auto_refresh_enabled
        }
        # Convert config to JSON and render the external template
        config_json_str = json.dumps(dashboard_config)
        return render_template('dash3-rc1.html', config_json=config_json_str)
    except Exception as e:
        logger.exception("Error rendering dashboard template 'dash3-rc1.html'")
        return f"<h1>Internal Server Error</h1><p>Failed to render dashboard template: {e}</p>", 500

# --- API Endpoints (/api/dashboard_data, /api/log_data, /api/fetch_older_logs, /api/toggle_log_refresh - Same as previous version) ---
@app.route('/api/dashboard_data')
def get_dashboard_data():
    logger.debug("Request received for /api/dashboard_data")
    try:
        data = state.get_snapshot_for_dashboard()
        if data.get('latest_stats') and data['latest_stats'].get('system'):
            data['latest_stats']['system']['dashboard_start_time'] = state.server_start_time.isoformat()
        return jsonify(data)
    except Exception as e: logger.exception("Error in /api/dashboard_data"); return jsonify({"error": "Failed to get dashboard data", "detail": str(e)}), 500

@app.route('/api/log_data')
def get_log_data():
    logger.debug("Request received for /api/log_data (latest)")
    try: return jsonify(state.get_log_data_for_request())
    except Exception as e: logger.exception("Error in /api/log_data"); return jsonify({"error": "Failed to get log data", "detail": str(e)}), 500

@app.route('/api/fetch_older_logs')
def get_older_logs():
    logger.debug("Request received for /api/fetch_older_logs")
    thread = threading.Thread(target=fetch_log_content_job, args=(True,), name="FetchOlderLogsThread"); thread.start()
    logger.info("Dispatched thread to fetch older logs.")
    try: return jsonify(state.get_log_data_for_request()) # Return current state immediately
    except Exception as e: logger.exception("Error preparing data after triggering older log fetch"); return jsonify({"error": "Failed state after triggering fetch", "detail": str(e)}), 500

@app.route('/api/toggle_log_refresh', methods=['POST'])
def toggle_log_refresh():
    logger.debug("Request received for /api/toggle_log_refresh")
    try:
        data = request.get_json();
        if data is None or 'enabled' not in data: return jsonify({"error": "Missing 'enabled' field"}), 400
        enabled = bool(data.get('enabled', False)); state.set_log_auto_refresh(enabled)
        return jsonify({"success": True, "enabled": enabled})
    except Exception as e: logger.exception("Error toggling log refresh"); return jsonify({"error": "Failed to toggle log refresh", "detail": str(e)}), 500


# --- Main Execution (Same as before, using Waitress if available) ---
if __name__ == '__main__':
    is_local_api = "127.0.0.1" in API_BASE_URL or "localhost" in API_BASE_URL
    if is_local_api:
        try: import urllib3; urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning); logger.warning("SSL verification disabled for local API.")
        except Exception as e: logger.warning(f"Could not disable urllib3 warnings: {e}")

    scheduler_thread = threading.Thread(target=run_scheduler, name="SchedulerThread", daemon=True); scheduler_thread.start()

    logger.info(f" --- BrokerDash Pro Starting --- "); logger.info(f" Dashboard server running on http://0.0.0.0:{DASHBOARD_PORT}"); logger.info(f" API Base URL: {API_BASE_URL}"); logger.info(f" API User: {API_USERNAME}"); logger.info(f" Verify API SSL: {not is_local_api}"); logger.info(f" Template Folder: dash-templates"); logger.info(f" ----------------------------- ")

    try:
        try:
            from waitress import serve
            logger.info("Starting server with Waitress..."); serve(app, host='0.0.0.0', port=DASHBOARD_PORT, threads=12)
        except ImportError:
            logger.warning("Waitress not found. Using Flask's development server (NOT FOR PRODUCTION).")
            app.run(host='0.0.0.0', port=DASHBOARD_PORT, debug=False, use_reloader=False)
    except KeyboardInterrupt: logger.info("Dashboard server stopped by user.")
    except Exception as e: logger.critical(f"Dashboard server failed: {e}", exc_info=True)

    logger.info("BrokerDash Pro server exiting.")