# dashboard_server_pro_separated_pipeline.py
# Version: 4.1 (Pipeline Architecture with extensive comments)
# Description: A Flask-based dashboard server that polls a target API,
#              processes the data in a separate thread using queues,
#              and serves the processed data to a web frontend.
#              This version focuses on detailed explanations and structure.

# Standard library imports
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
import traceback
import queue
import sys # For system-level information (optional, can add more details)

# Third-party library imports
import requests
from flask import Flask, Response, jsonify, render_template, request
from flask_cors import CORS

# ==============================================================================
# Configuration Constants
# ==============================================================================
# These settings control the behavior of the dashboard server.
# Environment variables are used where possible for flexibility.

# --- Network Configuration ---
DASHBOARD_PORT = int(os.environ.get("DASHBOARD_PORT", 8333)) # Port for this dashboard server
API_BASE_URL = os.environ.get("API_BASE_URL", "https://127.0.0.1:8777").rstrip('/') # URL of the target API

# --- Target API Endpoints ---
# Construct specific API endpoint URLs based on the base URL
API_STATS_URL = f"{API_BASE_URL}/stats"
API_LOGIN_URL = f"{API_BASE_URL}/login"
API_QUEUES_URL = f"{API_BASE_URL}/queues"
API_LOGS_LIST_URL = f"{API_BASE_URL}/logs" # Endpoint to list available log files
API_LOG_CONTENT_URL = f"{API_BASE_URL}/logs" # Base URL for log content (e.g., /logs/{filename})

# --- Target API Authentication ---
# Credentials for logging into the target API
API_USERNAME = os.environ.get("API_USER", "admin")
API_PASSWORD = os.environ.get("API_PASS", "admin")

# --- Polling Intervals (in seconds) ---
# How often the backend polls the target API for different data types
POLL_STATS_INTERVAL_SECONDS = 5      # Frequency for main statistics
POLL_QUEUES_INTERVAL_SECONDS = 15     # Frequency for queue details
POLL_LOGLIST_INTERVAL_SECONDS = 60    # Frequency for available log files list
POLL_LOGCONTENT_INTERVAL_SECONDS = 30 # Frequency for auto-refreshing log content (if enabled)

# --- Data History and Limits ---
MAX_CHART_HISTORY = 360      # Max data points for time-series charts (e.g., 360 * 5s = 30 mins)
LOG_CHUNK_SIZE = 250         # Number of log lines to fetch per request
MAX_LOG_LINES_MEMORY = 5000  # Max log lines stored in the server's memory deque
RAW_DATA_QUEUE_MAX_SIZE = 5  # Max items in intermediate queues (prevents memory bloat if processing lags)
                               # Log content queue has a multiplier applied later.

# --- Request Behavior ---
REQUESTS_TIMEOUT = 15        # Timeout in seconds for requests to the target API

# ==============================================================================
# Logging Configuration
# ==============================================================================
# Set up consistent logging format and levels for the application.

logging.basicConfig(
    level=logging.INFO, # Default level (can be changed via env var if needed)
    format='%(asctime)s - %(threadName)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('BrokerDashPro') # Main application logger

# Silence overly verbose logs from underlying libraries
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger('werkzeug').setLevel(logging.WARNING) # Quieten Flask's default request logs

logger.info("Logging configured.")

# ==============================================================================
# Global State Management (DashboardState Class)
# ==============================================================================
# This class encapsulates all the shared state that needs to be accessed
# by different threads (polling, processing, Flask API). It uses locks
# to ensure thread safety.

class DashboardState:
    """
    Manages the shared state of the dashboard, including raw data queues,
    processed data, historical data, API credentials, and error status.
    Ensures thread-safe access to shared resources using locks.
    """

    def __init__(self, max_history, log_chunk_size):
        """
        Initializes the DashboardState.

        Args:
            max_history (int): The maximum number of data points for historical charts.
            log_chunk_size (int): The number of log lines fetched per request.
        """
        logger.debug("Initializing DashboardState...")

        # --- Thread Synchronization ---
        # Primary lock for general state access (latest data, config, errors)
        self.lock = Lock()
        # Note: Removed separate processing_lock for simplicity, using careful locking in processing methods instead.

        # --- Intermediate Raw Data Queues ---
        # These queues hold data fetched by polling threads before processing.
        # Maxsize prevents unbounded memory growth if processing falls behind polling.
        logger.debug(f"Initializing raw data queues with max size: {RAW_DATA_QUEUE_MAX_SIZE} (logs: x2)")
        self.raw_stats_queue = queue.Queue(maxsize=RAW_DATA_QUEUE_MAX_SIZE)
        self.raw_queues_queue = queue.Queue(maxsize=RAW_DATA_QUEUE_MAX_SIZE)
        self.raw_loglist_queue = queue.Queue(maxsize=RAW_DATA_QUEUE_MAX_SIZE)
        self.raw_logcontent_queue = queue.Queue(maxsize=RAW_DATA_QUEUE_MAX_SIZE * 2) # Allow more buffer for logs

        # --- Processed State Data (Served by Flask API) ---
        # This data is updated by the processing thread and read by API endpoints.
        logger.debug("Initializing processed data attributes.")
        self.latest_stats = {}                  # Most recent statistics payload from API
        self.latest_queues = []                 # Most recent list of queue objects
        self.last_successful_stats_update = None  # Timestamp of last successful stats processing
        self.last_successful_queues_update = None # Timestamp of last successful queues processing
        self.last_successful_loglist_update = None# Timestamp of last successful log list processing
        self.last_successful_logcontent_update = None # Timestamp of last successful log content processing

        # --- Error Handling State ---
        logger.debug("Initializing error tracking attributes.")
        self.last_api_error = None             # Tracks generic/authentication errors affecting all API calls
        self.last_fetch_error = {}             # Tracks errors specific to fetching each data type (e.g., {"stats": {...}})
        self.last_processing_error = None      # Tracks errors occurring during data processing

        # --- Authentication & Timing ---
        logger.debug("Initializing authentication and timing attributes.")
        self.api_access_token = None           # Stores the Bearer token for API access
        self.login_needed = True               # Flag indicating if login is required before next API call
        self.server_start_time = datetime.now(timezone.utc) # Timestamp when this dashboard server started
        self.last_calc_timestamp = None        # Timestamp of the last stats data used for rate calculation

        # --- History Deques for Charts ---
        # Store time-series data for dashboard charts. 'maxlen' ensures they don't grow indefinitely.
        logger.debug(f"Initializing history deques with max length: {max_history}")
        self.max_history = max_history
        self.time_labels = deque(maxlen=max_history)              # X-axis labels (HH:MM:SS)
        self.request_rate_history = deque(maxlen=max_history)     # Rate (events/sec)
        self.processed_rate_history = deque(maxlen=max_history)   # Rate (events/sec)
        self.failed_rate_history = deque(maxlen=max_history)      # Rate (events/sec)
        self.message_status_history = {                           # Absolute counts
            "pending": deque(maxlen=max_history), "processing": deque(maxlen=max_history),
            "failed": deque(maxlen=max_history), "processed": deque(maxlen=max_history)
        }
        self.performance_history = {                              # Percentages / MB
            "process_cpu": deque(maxlen=max_history), "process_memory": deque(maxlen=max_history), # In MB
            "system_cpu": deque(maxlen=max_history), "system_memory": deque(maxlen=max_history) # As %
        }
        self.http_error_rate_history = deque(maxlen=max_history)  # Rate (%)

        # --- State for Rate Calculations ---
        # Store previous values needed to calculate deltas for rates.
        logger.debug("Initializing rate calculation state variables.")
        self.previous_total_requests = 0
        self.previous_total_processed = 0
        self.previous_total_failed = 0
        self.previous_req_by_status = {} # Stores { 'status_code': count } from previous interval

        # --- Log Viewer State ---
        logger.debug("Initializing log viewer state attributes.")
        self.log_chunk_size = log_chunk_size                      # How many lines to fetch/process at once
        self.available_log_files = []                             # List of log filenames from the API
        self.current_log_filename = None                          # The log file currently selected in the UI
        self.log_lines = deque(maxlen=MAX_LOG_LINES_MEMORY)       # Stores the actual log line data for display
        self.log_next_fetch_start_line = None                     # Line number indicating where the next "fetch older" should start
        self.log_fetch_error_message = None                       # Specific error message related to log fetching/processing
        self.log_auto_refresh_enabled = True                      # Whether the log content should auto-refresh

        logger.info("DashboardState initialized successfully.")

    # --- Error Update/Clear Methods ---
    # These methods provide a thread-safe way to update/clear error states.

    def update_fetch_error(self, error_scope: str, message: str):
        """Records an error related to fetching data for a specific scope (e.g., 'stats', 'queues')."""
        with self.lock:
            timestamp = datetime.now(timezone.utc).isoformat()
            error_details = {"message": str(message), "timestamp": timestamp}
            self.last_fetch_error[error_scope] = error_details
            # Log the error with context
            logger.error(f"API Fetch Error Recorded (Scope: {error_scope}): {message}")

    def clear_fetch_error(self, error_scope: str):
        """Clears a fetch-specific error if it exists."""
        with self.lock:
            if error_scope in self.last_fetch_error:
                # Log the clearing action for debugging
                cleared_message = self.last_fetch_error[error_scope].get("message", "")[:50]
                del self.last_fetch_error[error_scope]
                logger.info(f"Cleared API fetch error (Scope: {error_scope}, Msg Snippet: '{cleared_message}...').")

    def update_processing_error(self, message: str):
        """Records an error related to data processing."""
        with self.lock:
            timestamp = datetime.now(timezone.utc).isoformat()
            self.last_processing_error = {"message": str(message), "timestamp": timestamp}
            logger.error(f"Processing Error Recorded: {message}")

    def clear_processing_error(self):
        """Clears the general processing error."""
        with self.lock:
            if self.last_processing_error:
                cleared_message = self.last_processing_error.get("message", "")[:50]
                self.last_processing_error = None
                logger.info(f"Cleared processing error (Msg Snippet: '{cleared_message}...').")

    # --- Rate Calculation Helpers ---
    # These are internal helpers used by process_raw_stats. They don't acquire locks themselves.

    def _calculate_rate(self, current_total, previous_total, interval_seconds):
        """Calculates the rate of change (per second) between two totals over an interval."""
        current_val = current_total if isinstance(current_total, (int, float)) else 0
        # Ensure previous_total is treated as 0 if it's None or invalid
        prev_val = previous_total if isinstance(previous_total, (int, float)) else 0
        delta = max(0, current_val - prev_val) # Ensure delta is non-negative
        rate = delta / interval_seconds if interval_seconds > 0 else 0.0 # Avoid division by zero
        return rate

    def _calculate_http_error_rate(self, current_req_by_status, previous_req_by_status, interval_seconds):
        """
        Calculates the HTTP error rate (percentage of 4xx/5xx responses) over the interval.
        Returns the rate and the cleaned dictionary of current statuses for the next calculation.
        """
        current_total_reqs = 0
        current_error_reqs = 0
        safe_current_status_dict = {}

        # Process current status counts safely
        for status, count in current_req_by_status.items():
            try:
                code_str = str(status)
                count_val = int(count)
                safe_current_status_dict[code_str] = count_val
                current_total_reqs += count_val
                if int(code_str) >= 400:
                    current_error_reqs += count_val
            except (ValueError, TypeError):
                logger.warning(f"Skipping invalid status/count in requests_by_status: {status}={count}")
                continue

        # Process previous status counts safely
        prev_total_reqs = sum(v for k, v in previous_req_by_status.items() if isinstance(v, int))
        prev_error_reqs = sum(v for k, v in previous_req_by_status.items() if isinstance(v, int) and k.isdigit() and int(k) >= 400)

        # Calculate deltas (changes over the interval)
        delta_total = max(0, current_total_reqs - prev_total_reqs)
        delta_errors = max(0, current_error_reqs - prev_error_reqs)

        # Calculate rate (%)
        error_rate = (delta_errors / delta_total * 100) if delta_total > 0 else 0.0

        # Return the calculated rate and the processed dictionary for the *next* interval's calculation
        return round(error_rate, 2), safe_current_status_dict

    # --- Data Processing Methods ---
    # These methods take raw data from the queues and update the processed state.

    def process_raw_stats(self, raw_stats: dict):
        """
        Processes raw statistics data, updates latest_stats, calculates rates,
        and appends data points to history deques. Optimized to minimize lock holding time.
        """
        logger.debug("Starting processing of raw stats...")
        start_time = time.monotonic()

        # --- Input Validation ---
        if not isinstance(raw_stats, dict) or not raw_stats:
            self.update_processing_error("Received empty or invalid raw stats data for processing.")
            logger.warning("Raw stats processing skipped due to invalid input format.")
            return

        # --- Prepare History Data (Lock-Free) ---
        now = datetime.now(timezone.utc)
        last_ts = self.last_calc_timestamp # Read timestamp (might be None initially)
        interval = (now - last_ts).total_seconds() if last_ts else 0.0

        new_history_points = {}
        calculation_successful = True
        next_previous_req_status = self.previous_req_by_status # Prepare for update

        if interval > 0.1: # Only calculate if interval is meaningful
            logger.debug(f"Calculating history points. Interval: {interval:.3f}s")
            try:
                # --- Calculations ---
                time_label = now.strftime("%H:%M:%S")
                req_rate = self._calculate_rate(raw_stats.get("requests_total"), self.previous_total_requests, interval)
                proc_rate = self._calculate_rate(raw_stats.get("messages_processed"), self.previous_total_processed, interval)
                fail_rate = self._calculate_rate(raw_stats.get("messages_failed"), self.previous_total_failed, interval)
                http_err_rate, next_previous_req_status_temp = self._calculate_http_error_rate(
                    raw_stats.get("requests_by_status", {}), self.previous_req_by_status, interval
                )

                # --- Assemble History Point ---
                new_history_points = {
                    'time_label': time_label,
                    'req_rate': round(req_rate, 2),
                    'proc_rate': round(proc_rate, 2),
                    'fail_rate': round(fail_rate, 2),
                    'http_err_rate': http_err_rate,
                    'msg_pending': raw_stats.get("messages_pending", 0),
                    'msg_processing': raw_stats.get("messages_processing", 0),
                    'msg_failed': raw_stats.get("messages_failed", 0),
                    'msg_processed': raw_stats.get("messages_processed", 0),
                    'perf_proc_cpu': round(safe_float(raw_stats.get("system", {}).get("process_cpu_percent")), 2),
                    'perf_proc_mem': round(safe_float(raw_stats.get("system", {}).get("process_memory_mb")), 2),
                    'perf_sys_cpu': round(safe_float(raw_stats.get("system", {}).get("cpu_percent")), 2),
                    'perf_sys_mem': round(safe_float(raw_stats.get("system", {}).get("memory_percent")), 2)
                }
                next_previous_req_status = next_previous_req_status_temp # Update if calculation succeeded
                calculation_successful = True

            except Exception as e:
                logger.error(f"Error calculating history points: {e}", exc_info=True)
                self.update_processing_error(f"Stats history calculation failed: {e}")
                calculation_successful = False # Signal that history update should be skipped
        else:
            logger.debug(f"Skipping history calculation due to small interval: {interval:.3f}s")
            calculation_successful = False

        prep_duration = time.monotonic() - start_time
        logger.debug(f"History data preparation took {prep_duration:.4f}s. Calculation successful: {calculation_successful}")

        # --- Update State (Minimal Lock Holding) ---
        update_start_time = time.monotonic()
        with self.lock:
            logger.debug("Acquired lock for stats state update.")
            # 1. Update latest stats (always do this)
            self.latest_stats = raw_stats
            self.last_successful_stats_update = now.isoformat()
            self.clear_fetch_error("stats") # Clear fetch error now that processing started

            # 2. Update history deques if calculations succeeded
            if calculation_successful and new_history_points:
                self.time_labels.append(new_history_points['time_label'])
                self.request_rate_history.append(new_history_points['req_rate'])
                self.processed_rate_history.append(new_history_points['proc_rate'])
                self.failed_rate_history.append(new_history_points['fail_rate'])
                self.http_error_rate_history.append(new_history_points['http_err_rate'])
                self.message_status_history["pending"].append(new_history_points['msg_pending'])
                self.message_status_history["processing"].append(new_history_points['msg_processing'])
                self.message_status_history["failed"].append(new_history_points['msg_failed'])
                self.message_status_history["processed"].append(new_history_points['msg_processed'])
                self.performance_history["process_cpu"].append(new_history_points['perf_proc_cpu'])
                self.performance_history["process_memory"].append(new_history_points['perf_proc_mem'])
                self.performance_history["system_cpu"].append(new_history_points['perf_sys_cpu'])
                self.performance_history["system_memory"].append(new_history_points['perf_sys_mem'])

                # 3. Update previous values needed for *next* calculation (must be under lock)
                self.previous_total_requests = raw_stats.get("requests_total", 0)
                self.previous_total_processed = raw_stats.get("messages_processed", 0)
                self.previous_total_failed = raw_stats.get("messages_failed", 0)
                self.previous_req_by_status = next_previous_req_status
                self.last_calc_timestamp = now # Update timestamp *only* if history was added

                self.clear_processing_error() # Clear processing error on full success
                logger.debug("History deques updated.")
            else:
                 logger.debug("History deques not updated (calculation skipped or failed).")

            lock_duration = time.monotonic() - update_start_time
            logger.debug(f"Stats state update lock held for {lock_duration:.4f}s.")

        total_duration = time.monotonic() - start_time
        logger.info(f"Raw stats processing finished in {total_duration:.4f}s.")


    def process_raw_queues(self, raw_queues: list):
        """Processes raw queue data, updating the latest_queues list."""
        logger.debug("Processing raw queues data...")
        start_time = time.monotonic()
        with self.lock:
            logger.debug("Acquired lock for queue state update.")
            if not isinstance(raw_queues, list):
                self.update_processing_error("Received non-list raw queues data for processing.")
                logger.warning("Raw queues processing skipped due to invalid input format.")
                return # Exit block

            # Sort queues alphabetically by name for consistent UI display
            self.latest_queues = sorted(raw_queues, key=lambda q: q.get('name', ''))
            self.last_successful_queues_update = datetime.now(timezone.utc).isoformat()

            # Clear relevant errors on success
            self.clear_processing_error()
            self.clear_fetch_error("queues")

            lock_duration = time.monotonic() - start_time
            logger.debug(f"Queue state update lock held for {lock_duration:.4f}s.")

        total_duration = time.monotonic() - start_time
        logger.info(f"Queues data processed successfully ({len(self.latest_queues)} queues) in {total_duration:.4f}s.")


    def process_raw_loglist(self, raw_log_data: dict):
        """Processes the list of available log files, updates state, and triggers initial fetch if needed."""
        logger.debug("Processing raw log list data...")
        start_time = time.monotonic()

        # --- Input Validation (Lock-Free) ---
        if not isinstance(raw_log_data, dict) or "log_files" not in raw_log_data or not isinstance(raw_log_data["log_files"], list):
            self.update_processing_error("Invalid raw log list format for processing.")
            logger.warning("Raw loglist processing skipped due to invalid input format.")
            return

        new_files_list = sorted(raw_log_data["log_files"], reverse=True) # Assume newest first preferred
        newly_selected_file_for_trigger = None # Store file name to trigger fetch outside lock

        # --- Update State (Under Lock) ---
        update_start_time = time.monotonic()
        with self.lock:
            logger.debug("Acquired lock for loglist state update.")
            # Check if the list actually changed
            if new_files_list != self.available_log_files:
                self.available_log_files = new_files_list
                logger.info(f"Log list updated: {len(new_files_list)} files available.")
            else:
                 logger.debug("Log list unchanged.")

            # Check status of the currently selected file
            current_selected_file = self.current_log_filename
            file_disappeared = current_selected_file and current_selected_file not in new_files_list
            no_file_currently_selected = not current_selected_file and new_files_list

            if file_disappeared:
                logger.warning(f"Currently viewed log file '{current_selected_file}' is no longer available. Clearing log view.")
                self.current_log_filename = None
                self.log_lines.clear()
                self.log_next_fetch_start_line = None
                self.log_fetch_error_message = "Current log file disappeared or was rotated."
                # Attempt to clear related items from the raw content queue (best effort)
                logger.debug("Attempting to clear raw log content queue due to file disappearance.")
                temp_queue = queue.Queue()
                while not self.raw_logcontent_queue.empty():
                    try:
                        item = self.raw_logcontent_queue.get_nowait()
                        if item.get("filename") != current_selected_file:
                            temp_queue.put_nowait(item) # Keep items for other files
                    except queue.Empty: break
                    except queue.Full: logger.warning("Temp queue full during log content clear"); break # Should not happen
                # Refill original queue
                while not temp_queue.empty():
                    try: self.raw_logcontent_queue.put_nowait(temp_queue.get_nowait())
                    except queue.Empty: break
                    except queue.Full: logger.warning("Raw log content queue full during refill"); break

            elif no_file_currently_selected:
                # Automatically select the newest available log file
                selected_file = new_files_list[0]
                logger.info(f"No log file was selected. Automatically selecting newest: '{selected_file}'")
                self.current_log_filename = selected_file
                self.log_lines.clear() # Clear any potential old lines
                self.log_next_fetch_start_line = None # Reset pagination for new file
                self.log_fetch_error_message = None # Clear errors from previous file
                newly_selected_file_for_trigger = selected_file # Mark for initial fetch trigger

            # Update timestamp and clear errors
            self.last_successful_loglist_update = datetime.now(timezone.utc).isoformat()
            self.clear_processing_error()
            self.clear_fetch_error("loglist")

            lock_duration = time.monotonic() - update_start_time
            logger.debug(f"Loglist state update lock held for {lock_duration:.4f}s.")

        # --- Trigger Initial Fetch (Lock-Free) ---
        if newly_selected_file_for_trigger:
            logger.info(f"Triggering initial content fetch for newly selected file: {newly_selected_file_for_trigger}")
            # Use the dedicated function which runs the fetch in a separate thread
            trigger_log_content_fetch(newly_selected_file_for_trigger, fetch_older=False)
        else:
             logger.debug("No new log file selected, initial fetch not triggered.")

        total_duration = time.monotonic() - start_time
        logger.info(f"Log list processing finished in {total_duration:.4f}s.")

    def process_raw_log_content(self, log_content_package: dict):
        """Processes raw log lines, updates the log deque, and manages pagination state."""
        logger.debug("Processing raw log content package...")
        start_time = time.monotonic()

        # --- Extract data from package (Lock-Free) ---
        filename = log_content_package.get("filename")
        new_lines = log_content_package.get("lines", [])
        is_prepend_request = log_content_package.get("fetch_older", False) # True if this was a "fetch older" request
        start_line_for_this_older_request = log_content_package.get("start_line_for_older")

        # --- Input Validation (Lock-Free) ---
        if not filename or not isinstance(new_lines, list):
            self.update_processing_error("Invalid raw log content data received (missing filename or lines not list).")
            logger.warning("Raw log content processing skipped due to invalid input package.")
            return

        # --- Update State (Under Lock) ---
        update_start_time = time.monotonic()
        with self.lock:
            logger.debug(f"Acquired lock for log content update ('{filename}').")
            # Only process if the lines are for the currently *selected* file in the UI state
            if filename != self.current_log_filename:
                logger.debug(f"Ignoring log content for '{filename}', current selection is '{self.current_log_filename}'. Discarding.")
                # Note: No need to clear errors here as the fetch itself might have been fine
                return # Exit lock and function

            # Clear previous log-specific fetch/processing error on receiving new data for the current file
            self.log_fetch_error_message = None

            processed_line_count = 0
            added_line_hashes = set() # Track hashes added in this batch to prevent duplicates within the batch

            # Determine the next start line for *future* older fetches based on this batch
            next_start_line_for_future_older = self.log_next_fetch_start_line # Default to existing value

            if is_prepend_request and start_line_for_this_older_request is not None:
                # This batch contains *older* logs.
                if len(new_lines) >= self.log_chunk_size:
                    # Got a full chunk of older logs. Assume more exist *before* this chunk.
                    # The next request for older logs should start *after* this block ends.
                    next_start_line_for_future_older = start_line_for_this_older_request + self.log_chunk_size
                    logger.debug(f"Older fetch got full chunk. Next older start set to: {next_start_line_for_future_older}")
                else:
                    # Received less than a full chunk, assume we reached the beginning of the file.
                    next_start_line_for_future_older = None # Disable "Load Older" button
                    logger.debug("Older fetch got partial chunk. Assuming start of file reached. Next older start set to None.")

            elif not is_prepend_request:
                # This batch contains the *latest* logs ('tail' request).
                if len(new_lines) >= self.log_chunk_size:
                    # Got a full chunk of latest logs. If "Load Older" isn't already enabled, enable it now.
                    if self.log_next_fetch_start_line is None:
                        # Heuristic: Assume older logs exist. First older fetch should start after this chunk.
                        next_start_line_for_future_older = self.log_chunk_size + 1
                        logger.debug(f"Latest fetch got full chunk. Enabling 'Load Older'. Next older start set to: {next_start_line_for_future_older}")
                elif self.log_next_fetch_start_line is None and len(self.log_lines) == 0 and len(new_lines) < self.log_chunk_size:
                     # Special case: Very first fetch ever for this file, and it was partial. Disable "Load Older".
                     next_start_line_for_future_older = None
                     logger.debug("Initial latest fetch got partial chunk. Disabling 'Load Older'. Next older start set to None.")
                # Otherwise (refreshing latest when older already available), keep existing older pointer.

            # Update the state variable for the next older fetch trigger
            self.log_next_fetch_start_line = next_start_line_for_future_older

            # --- Add lines to the deque ---
            # Use simple hash check for uniqueness within recent history / current batch
            # is_prepend_request=True means fetch_older=True, these lines are older, append to deque
            # is_prepend_request=False means fetch_older=False, these lines are newer, prepend to deque

            if is_prepend_request:
                 # Append older lines to the end of the deque (maintaining chronological order)
                 # Check against *all* existing hashes to avoid re-adding very old lines if fetches overlap strangely
                 existing_hashes = set(hash(f"{l.get('timestamp')}_{l.get('message')}") for l in self.log_lines)
                 logger.debug(f"Appending {len(new_lines)} older lines...")
                 # Iterate through received lines (API likely sends oldest first in the chunk)
                 for line in new_lines:
                     line_hash = hash(f"{line.get('timestamp')}_{line.get('message')}")
                     if line_hash not in existing_hashes and line_hash not in added_line_hashes:
                         self.log_lines.append(line) # Append older lines
                         added_line_hashes.add(line_hash)
                         processed_line_count += 1
                 if processed_line_count > 0:
                     logger.debug(f"Appended {processed_line_count}/{len(new_lines)} unique older log lines for '{filename}'.")

            else:
                 # Prepend newer lines to the start of the deque
                 # Check only against *recent* existing hashes for performance
                 existing_recent_hashes = set(hash(f"{l.get('timestamp')}_{l.get('message')}") for l in list(self.log_lines)[:LOG_CHUNK_SIZE*2])
                 logger.debug(f"Prepending {len(new_lines)} newer lines...")
                 unique_lines_to_add = []
                 # Iterate through received lines (API likely sends newest first)
                 for line in new_lines:
                     line_hash = hash(f"{line.get('timestamp')}_{line.get('message')}")
                     if line_hash not in existing_recent_hashes and line_hash not in added_line_hashes:
                         unique_lines_to_add.append(line)
                         # Add to *both* sets to check against current batch and recent history
                         added_line_hashes.add(line_hash)
                         existing_recent_hashes.add(line_hash)

                 # Prepend the unique new lines in reverse order to maintain newest-first order in deque
                 for line in reversed(unique_lines_to_add):
                       self.log_lines.appendleft(line) # Prepend newer lines
                       processed_line_count += 1
                 if processed_line_count > 0:
                     logger.debug(f"Prepended {processed_line_count}/{len(unique_lines_to_add)} unique new log lines for '{filename}'.")

            # Update timestamp and clear fetch error
            self.last_successful_logcontent_update = datetime.now(timezone.utc).isoformat()
            self.clear_fetch_error("logcontent") # Clear fetch error on successful processing
            # Do not clear general processing error here, might be other issues.

            lock_duration = time.monotonic() - update_start_time
            logger.debug(f"Log content update lock for '{filename}' held for {lock_duration:.4f}s.")

        total_duration = time.monotonic() - start_time
        logger.info(f"Log content processing for '{filename}' finished in {total_duration:.4f}s. Processed lines: {processed_line_count}")


    # --- Authentication and State Getters/Setters ---
    # These provide controlled access to specific state variables.

    def set_log_auto_refresh(self, enabled: bool):
        """Sets the log auto-refresh flag thread-safely."""
        with self.lock:
            if self.log_auto_refresh_enabled != enabled:
                self.log_auto_refresh_enabled = enabled
                logger.info(f"Log auto-refresh explicitly set to: {enabled}")
            else:
                logger.debug(f"Log auto-refresh already set to: {enabled}")

    def needs_login(self):
        """Checks if an API login is currently required."""
        with self.lock:
            return self.login_needed or not self.api_access_token

    def get_token(self):
        """Returns the current API access token (thread-safe)."""
        with self.lock:
            return self.api_access_token

    def set_token(self, token: str):
        """Sets the API access token and updates login status (thread-safe)."""
        with self.lock:
            self.api_access_token = token
            self.login_needed = False
            # Clear any generic auth errors on successful token set
            if self.last_api_error and self.last_api_error.get("type") == "auth":
                logger.info(f"Clearing previous auth error on successful token set: {self.last_api_error.get('message')}")
                self.last_api_error = None
            logger.info("API access token set successfully.")

    def invalidate_token(self, reason: str = "Authentication failed"):
        """Invalidates the current token and forces login (thread-safe)."""
        with self.lock:
            token_was_present = bool(self.api_access_token)
            self.api_access_token = None
            self.login_needed = True
            timestamp = datetime.now(timezone.utc).isoformat()
            # Record the reason as a generic auth error
            self.last_api_error = {"message": str(reason), "type": "auth", "timestamp": timestamp}
            if token_was_present:
                logger.warning(f"API token invalidated: {reason}")
            else:
                logger.info(f"Setting login needed state: {reason}")

    def get_snapshot_for_dashboard(self):
        """Returns a snapshot of the current processed state for the dashboard API (thread-safe)."""
        logger.debug("Creating dashboard data snapshot...")
        start_time = time.monotonic()
        with self.lock:
            logger.debug("Acquired lock for snapshot creation.")
            # Create copies of mutable objects (lists, deques, dicts) to avoid race conditions during serialization
            history_copy = {
                "time_labels": list(self.time_labels),
                "request_rate_history": list(self.request_rate_history),
                "processed_rate_history": list(self.processed_rate_history),
                "failed_rate_history": list(self.failed_rate_history),
                "message_status": {k: list(v) for k, v in self.message_status_history.items()},
                "performance": {k: list(v) for k, v in self.performance_history.items()},
                "http_error_rate_history": list(self.http_error_rate_history)
            }

            # Combine and sort all error types for display
            all_errors = []
            if self.last_api_error: all_errors.append(self.last_api_error)
            # Prefix fetch errors with scope for clarity in UI
            for scope, err in self.last_fetch_error.items():
                all_errors.append({"message": f"[Fetch:{scope}] {err['message']}", "type": f"fetch_{scope}", "timestamp": err['timestamp']})
            if self.last_processing_error: all_errors.append(self.last_processing_error)
            all_errors.sort(key=lambda x: x.get('timestamp', ''), reverse=True) # Newest first

            # Copy latest stats and add dashboard start time for uptime calculation
            latest_stats_copy = self.latest_stats.copy()
            if 'system' not in latest_stats_copy: latest_stats_copy['system'] = {} # Ensure system key exists
            latest_stats_copy['system']['dashboard_start_time'] = self.server_start_time.isoformat()

            snapshot = {
                "latest_stats": latest_stats_copy,
                "latest_queues": self.latest_queues[:], # Shallow copy of list
                "history": history_copy,
                "current_log_filename": self.current_log_filename,
                "log_fetch_error": self.log_fetch_error_message, # Log-specific error
                "last_successful_stats_update": self.last_successful_stats_update,
                "last_successful_queues_update": self.last_successful_queues_update,
                "last_api_error": all_errors[0] if all_errors else None, # Most recent overall error
                "all_api_errors": all_errors, # Optionally send all recent errors
                "log_auto_refresh_enabled": self.log_auto_refresh_enabled,
                "available_log_files": self.available_log_files[:], # Shallow copy
                "log_next_fetch_start_line": self.log_next_fetch_start_line,
                "server_start_time": self.server_start_time.isoformat() # For reference
            }
            lock_duration = time.monotonic() - start_time
            logger.debug(f"Snapshot lock held for {lock_duration:.4f}s.")

        total_duration = time.monotonic() - start_time
        logger.debug(f"Dashboard snapshot created in {total_duration:.4f}s.")
        return snapshot

    def get_log_data_for_request(self):
        """Returns the current log data state for the log API endpoint (thread-safe)."""
        logger.debug("Getting log data snapshot...")
        start_time = time.monotonic()
        with self.lock:
             # Return copies or immutable versions where appropriate
             log_snapshot = {
                 "filename": self.current_log_filename,
                 "lines": list(self.log_lines), # Return current buffer as a list copy
                 "next_fetch_start_line": self.log_next_fetch_start_line,
                 "log_fetch_error": self.log_fetch_error_message,
                 "last_successful_logcontent_update": self.last_successful_logcontent_update,
                 "log_auto_refresh_enabled": self.log_auto_refresh_enabled
             }
        duration = time.monotonic() - start_time
        logger.debug(f"Log data snapshot created in {duration:.4f}s.")
        return log_snapshot

# ==============================================================================
# Utility Functions
# ==============================================================================
# Helper functions for data formatting and safe operations.

def safe_float(value, default=0.0):
    """Safely attempts to convert a value to a float, returning default on failure."""
    if value is None:
        return default
    try:
        return float(value)
    except (ValueError, TypeError):
        # logger.debug(f"Could not convert '{value}' to float.", exc_info=True) # Optional: Log conversion failures
        return default

def format_timedelta_human(seconds: int | float | None) -> str:
    """Converts seconds into a human-readable string like '1d 2h 3m 4s' or '--'."""
    if seconds is None or not isinstance(seconds, (int, float)) or seconds < 0:
        return "--"
    seconds = int(seconds) # Work with integers
    if seconds < 1:
        return "< 1 sec"

    days, remainder = divmod(seconds, 86400)  # 60 * 60 * 24
    hours, remainder = divmod(remainder, 3600)  # 60 * 60
    minutes, secs = divmod(remainder, 60)

    parts = []
    if days > 0: parts.append(f"{days}d")
    if hours > 0: parts.append(f"{hours}h")
    if minutes > 0: parts.append(f"{minutes}m")
    # Show seconds only if other parts exist and secs > 0, OR if no other parts (e.g., < 1 min)
    if secs > 0 or not parts: parts.append(f"{secs}s")

    return " ".join(parts) if parts else "0s" # Ensure "0s" if duration is exactly 0

def bytes_to_human(n_bytes: int | float | None, precision: int = 1) -> str:
    """Converts bytes to a human-readable string (KB, MB, GB...) or '--'."""
    if n_bytes is None or not isinstance(n_bytes, (int, float)) or n_bytes < 0:
        return "--"
    try:
        # Ensure we work with integer bytes for calculation
        n_bytes = int(n_bytes)
    except (ValueError, TypeError):
        return "--" # Cannot convert input to int

    if n_bytes == 0:
        return "0 B"

    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']
    try:
        # Calculate power safely, handle log(0) case implicitly by n_bytes > 0 check
        power = min(int(math.log(n_bytes, 1024)), len(units) - 1) if n_bytes > 0 else 0
        value = n_bytes / (1024 ** power)
        # Format the value with specified precision
        return f"{value:.{precision}f} {units[power]}"
    except ZeroDivisionError:
        # Should not happen with the power calculation logic, but handle defensively
        return f"{n_bytes} B"
    except Exception as e:
        # Catch any unexpected formatting errors
        logger.warning(f"Error formatting bytes: {n_bytes} - {e}", exc_info=True)
        return "--"

# ==============================================================================
# API Interaction Logic
# ==============================================================================
# Functions responsible for communicating with the target API.
# Includes authentication, fetching data, and handling errors.

# --- API Error Handling Decorator ---
def handle_api_errors_for_fetch(error_scope="generic"):
    """
    Decorator for API fetching functions. Handles authentication checks,
    common request exceptions, and updates fetch-specific errors in the state.
    Injects 'headers' and 'verify_ssl' into the decorated function's call.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # This wrapper executes *before* the decorated fetch function (e.g., fetch_stats_raw_data)
            global state
            token = None
            function_name = func.__name__
            logger.debug(f"Decorator @handle_api_errors_for_fetch executing for {function_name} (Scope: {error_scope})")

            # --- Authentication Check ---
            if state.needs_login():
                logger.info(f"Login required for {function_name}, attempting...")
                if not login_to_api(): # login_to_api handles its own errors/state updates
                    # If login fails, update the fetch error for *this* scope as well
                    state.update_fetch_error(error_scope, "Dependency failed: API Login")
                    logger.error(f"Aborting {function_name}: Required API login failed.")
                    return False # Indicate fetch failure due to login issue

                # Login succeeded, retrieve the token
                token = state.get_token()
                if not token:
                    # This is an internal error state if login succeeded but token is missing
                    error_msg = f"Internal Error: Token missing after successful login attempt for {function_name}."
                    logger.error(error_msg)
                    state.update_fetch_error(error_scope, error_msg)
                    return False
            else:
                # Already logged in (or token exists), retrieve token
                token = state.get_token()
                if not token:
                    # If token is somehow None even when login wasn't marked as needed
                    error_msg = f"Internal Error: Token unexpectedly None for {function_name} despite not needing login."
                    logger.error(error_msg)
                    state.update_fetch_error(error_scope, error_msg)
                    state.invalidate_token("Token missing unexpectedly") # Force re-login next time
                    return False

            # --- Prepare Request Parameters ---
            headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/json'}
            # Determine if SSL verification should be disabled (only for localhost/127.0.0.1)
            is_local_api = "127.0.0.1" in API_BASE_URL or "localhost" in API_BASE_URL
            verify_ssl = not is_local_api
            logger.debug(f"Prepared for API call: Verify SSL={verify_ssl}")

            # --- Execute Decorated Function ---
            try:
                # Inject headers and verify_ssl into the called function's arguments
                # The decorated function's signature must accept these.
                kwargs['headers'] = headers
                kwargs['verify_ssl'] = verify_ssl

                # Call the actual fetch function (e.g., fetch_stats_raw_data)
                result = func(*args, **kwargs) # result should be True on success, False on logical failure within func

                # If the fetch function itself returned True (indicating success), clear its specific error
                if result:
                    logger.debug(f"Fetch function {function_name} returned success (True). Clearing fetch error for scope '{error_scope}'.")
                    state.clear_fetch_error(error_scope)
                else:
                     logger.warning(f"Fetch function {function_name} returned failure (False or None). Fetch error (if any) for scope '{error_scope}' will persist.")

                return result # Pass back the True/False result from the fetch function

            # --- Exception Handling Block ---
            # Catch specific exceptions from the 'requests' library and general errors.
            except requests.exceptions.Timeout as e:
                error_msg = f"API request timed out calling {function_name}: {e}"
                logger.warning(error_msg)
                state.update_fetch_error(error_scope, error_msg)
            except requests.exceptions.SSLError as e:
                error_msg = f"API SSL Error during {function_name}: {e}. Check target API certificate/URL."
                logger.error(error_msg)
                state.update_fetch_error(error_scope, error_msg)
            except requests.exceptions.ConnectionError as e:
                error_msg = f"API Connection Error during {function_name}: {e}. Cannot reach {API_BASE_URL}"
                logger.error(error_msg)
                state.update_fetch_error(error_scope, error_msg)
            except requests.exceptions.HTTPError as e:
                # Handle HTTP errors (4xx, 5xx)
                status_code = getattr(e.response, 'status_code', 'N/A')
                response_text = ""
                try:
                    response_text = e.response.text[:200] if e.response is not None else "N/A"
                except Exception: pass # Ignore errors getting response text
                error_detail = f"API HTTP Error ({status_code}) in {function_name}: {e}. Response snippet: {response_text}"
                logger.warning(error_detail)

                if status_code in [401, 403]: # Specific handling for authentication/authorization errors
                    logger.warning(f"API authentication/authorization error ({status_code}) detected for {function_name}. Invalidating token.")
                    # Invalidate the token to force re-login on the next attempt
                    state.invalidate_token(f"API Auth error ({status_code}) calling {function_name}")
                    # Also record the fetch error for this specific scope
                    state.update_fetch_error(error_scope, f"Authentication error ({status_code})")
                else:
                    # For other HTTP errors (e.g., 404, 500), just record the fetch error
                    state.update_fetch_error(error_scope, error_detail)
            except requests.exceptions.RequestException as e:
                # Catch other general request exceptions (e.g., invalid URL, DNS issues)
                error_msg = f"General API Request Failed during {function_name}: {e}"
                logger.error(error_msg)
                state.update_fetch_error(error_scope, error_msg)
            except json.JSONDecodeError as e:
                # Handle errors parsing the JSON response from the API
                error_msg = f"Failed to decode JSON response from API in {function_name}. Error: {e}"
                logger.error(error_msg)
                state.update_fetch_error(error_scope, error_msg)
            except Exception as e:
                # Catch any other unexpected errors during the fetch call
                logger.exception(f"Unexpected error during API fetch function {function_name}") # Log full traceback
                state.update_fetch_error(error_scope, f"Unexpected error in {function_name}: {type(e).__name__} - {e}")

            # If any exception occurred in the try block, return False to signal failure
            logger.debug(f"Decorator handling complete for {function_name}. Returning False due to caught exception.")
            return False
        return wrapper
    return decorator

# --- Authentication Function ---
def login_to_api() -> bool:
    """
    Attempts to authenticate with the target API using configured credentials.
    Updates the global state with the access token on success.
    Handles authentication errors and updates the error state.

    Returns:
        bool: True if login was successful and token was set, False otherwise.
    """
    global state
    logger.info(f"Attempting login via POST to {API_LOGIN_URL}...")
    verify_ssl = not ("127.0.0.1" in API_BASE_URL or "localhost" in API_BASE_URL)
    login_successful = False
    try:
        # Make the POST request to the login endpoint
        response = requests.post(
            API_LOGIN_URL,
            data={'username': API_USERNAME, 'password': API_PASSWORD},
            verify=verify_ssl,
            timeout=REQUESTS_TIMEOUT
        )
        # Raise an exception for bad status codes (e.g., 401, 403, 500)
        response.raise_for_status()
        # Parse the JSON response
        token_data = response.json()

        # Check if the expected 'access_token' key is present
        if "access_token" in token_data and token_data["access_token"]:
            state.set_token(token_data["access_token"]) # Updates state, clears auth error
            login_successful = True
            logger.info("API login successful.")
        else:
            # Log error and update state if token is missing
            error_msg = "Login response successful (2xx) but missing 'access_token' field."
            logger.error(error_msg)
            state.update_fetch_error("auth", error_msg) # Use fetch error for consistency

    except requests.exceptions.HTTPError as e:
        # Handle specific HTTP errors during login
        status_code = getattr(e.response, 'status_code', 'N/A')
        detail = f"Status Code: {status_code}"
        try: # Attempt to get more detail from the response body
            if e.response is not None:
                detail += f" - Response: {e.response.json().get('detail', e.response.text[:100])}"
        except (json.JSONDecodeError, AttributeError):
            try: detail += f" - Response: {e.response.text[:100]}"
            except AttributeError: pass # No response object available
        logger.error(f"API login HTTP error ({detail}): {e}")
        state.update_fetch_error("auth", f"API login failed ({detail})")
    except requests.exceptions.RequestException as e:
        # Handle network-level errors (connection, timeout, etc.)
        logger.error(f"API login request failed (Network/Request Error): {e}")
        state.update_fetch_error("auth", f"API login request failed: {e}")
    except json.JSONDecodeError as e:
        # Handle errors parsing the login response
        logger.error(f"Failed to decode API login response JSON: {e}")
        state.update_fetch_error("auth", "Invalid JSON response during login")
    except Exception as e:
        # Catch any other unexpected errors during login
        logger.exception("Unexpected error during API login process")
        state.update_fetch_error("auth", f"Unexpected login error: {e}")

    # Ensure token is invalidated if login ultimately failed for any reason
    if not login_successful:
        logger.warning("Login attempt concluded unsuccessfully.")
        state.invalidate_token("Login attempt failed") # invalidate_token handles setting generic auth error

    return login_successful


# --- Data Fetching Functions (Raw Data) ---
# These functions perform the actual API calls to fetch raw data.
# They are decorated with @handle_api_errors_for_fetch for error handling and auth.
# They put the raw data onto the appropriate queue in DashboardState on success.

@handle_api_errors_for_fetch(error_scope="stats")
def fetch_stats_raw_data(headers: dict, verify_ssl: bool) -> bool:
    """Fetches raw stats data and puts it into the raw_stats_queue."""
    global state
    logger.debug("Executing fetch_stats_raw_data...")
    # Make the GET request
    response = requests.get(API_STATS_URL, headers=headers, verify=verify_ssl, timeout=REQUESTS_TIMEOUT)
    response.raise_for_status() # Handled by decorator, but good practice
    # Parse JSON response
    raw_stats_data = response.json()
    # Try to add the fetched data to the queue
    try:
        state.raw_stats_queue.put_nowait(raw_stats_data)
        logger.debug(f"Raw stats data added to queue (current size={state.raw_stats_queue.qsize()})")
        return True # Indicate success
    except queue.Full:
        logger.warning("Raw stats queue is full. Discarding newly fetched data.")
        # Optionally: Implement handling for full queue (e.g., log丢弃, wait, etc.)
        return False # Indicate data was not queued


@handle_api_errors_for_fetch(error_scope="queues")
def fetch_queues_raw_data(headers: dict, verify_ssl: bool) -> bool:
    """Fetches raw queue data and puts it into the raw_queues_queue."""
    global state
    logger.debug("Executing fetch_queues_raw_data...")
    response = requests.get(API_QUEUES_URL, headers=headers, verify=verify_ssl, timeout=REQUESTS_TIMEOUT)
    response.raise_for_status()
    raw_queues_data = response.json()
    try:
        state.raw_queues_queue.put_nowait(raw_queues_data)
        logger.debug(f"Raw queues data added to queue (current size={state.raw_queues_queue.qsize()})")
        return True
    except queue.Full:
        logger.warning("Raw queues queue is full. Discarding newly fetched data.")
        return False


@handle_api_errors_for_fetch(error_scope="loglist")
def fetch_loglist_raw_data(headers: dict, verify_ssl: bool) -> bool:
    """Fetches the list of available log files and puts it into the raw_loglist_queue."""
    global state
    logger.debug("Executing fetch_loglist_raw_data...")
    response = requests.get(API_LOGS_LIST_URL, headers=headers, verify=verify_ssl, timeout=REQUESTS_TIMEOUT)
    response.raise_for_status()
    raw_loglist_data = response.json() # Expects {"log_files": [...]}
    try:
        state.raw_loglist_queue.put_nowait(raw_loglist_data)
        logger.debug(f"Raw loglist data added to queue (current size={state.raw_loglist_queue.qsize()})")
        return True
    except queue.Full:
        logger.warning("Raw loglist queue is full. Discarding newly fetched data.")
        return False


@handle_api_errors_for_fetch(error_scope="logcontent")
def fetch_log_content_raw_data(filename: str, fetch_older: bool, headers: dict, verify_ssl: bool) -> bool:
    """
    Fetches a chunk of log content (either latest or older) for a specific file
    and puts it into the raw_logcontent_queue.
    """
    global state
    logger.debug(f"Executing fetch_log_content_raw_data for '{filename}', fetch_older={fetch_older}")
    params = {}
    start_line_for_older_request = None # Context for the processing step

    # --- Determine API Parameters based on request type ---
    with state.lock: # Need lock briefly to read log_next_fetch_start_line
        if fetch_older:
            older_start_num = state.log_next_fetch_start_line
            if older_start_num and older_start_num > 0:
                # Parameters for fetching older logs (adjust based on API spec: start/end or start/limit)
                params['start'] = older_start_num
                params['limit'] = state.log_chunk_size # Assuming API uses limit
                # If API uses end: params['end'] = older_start_num + state.log_chunk_size - 1
                start_line_for_older_request = older_start_num # Record the requested start line
                logger.debug(f"Configured fetch older parameters for '{filename}': start={older_start_num}, limit={params['limit']}")
            else:
                # If no valid start line for older logs, assume we can't fetch more.
                logger.info(f"Skipping fetch older logs for '{filename}': No valid 'next_fetch_start_line' found ({state.log_next_fetch_start_line}). Assuming beginning of file reached.")
                # Return True because it's not a fetch *error*, just nothing more to get.
                # This prevents the fetch error state from being set unnecessarily.
                return True
        else:
            # Parameters for fetching the latest logs (e.g., using 'tail')
            params['tail'] = state.log_chunk_size
            # If API uses limit instead: params['limit'] = state.log_chunk_size
            logger.debug(f"Configured fetch latest parameters for '{filename}': tail={params['tail']}")

    # --- Make the API Request ---
    logger.info(f"Fetching raw log content from API for '{filename}' with params: {params}")
    # Basic URL encoding for filename (replace with urllib.parse.quote if needed)
    safe_filename = filename.replace('/', '%2F')
    log_content_url = f"{API_LOG_CONTENT_URL}/{safe_filename}"

    response = requests.get(
        log_content_url,
        headers=headers,
        params=params,
        verify=verify_ssl,
        timeout=REQUESTS_TIMEOUT + 10 # Allow slightly longer for log fetches
    )

    # --- Handle Specific HTTP Errors (e.g., 404 Not Found) ---
    try:
        response.raise_for_status() # Check for 4xx/5xx errors first
    except requests.exceptions.HTTPError as e:
         if e.response is not None and e.response.status_code == 404:
             # Log file not found - this is a specific case, not necessarily a global error
             logger.warning(f"Log file '{filename}' not found (404) when fetching content. It might have been rotated or deleted.")
             # Update the log-specific error message in the state
             with state.lock:
                 state.log_fetch_error_message = f"Log file '{filename}' not found (404)."
             # Return False to indicate this specific fetch failed, but let decorator handle generic HTTP error logging if needed.
             return False
         else:
             # Re-raise other HTTP errors to be handled by the main decorator logic
             logger.error(f"Unhandled HTTPError ({e.response.status_code if e.response else 'N/A'}) fetching log content for {filename}: {e}")
             raise e

    # --- Process Successful Response ---
    raw_log_lines = response.json() # Assume API returns a list of lines (or objects)

    # Package the data along with context for the processing thread
    log_content_package = {
        "filename": filename,
        "lines": raw_log_lines,
        "fetch_older": fetch_older, # Context: Was this an older log request?
        "start_line_for_older": start_line_for_older_request # Context: What start line was used?
    }

    # Add the package to the queue
    try:
        state.raw_logcontent_queue.put_nowait(log_content_package)
        logger.debug(f"Raw log content package for '{filename}' added to queue (current size={state.raw_logcontent_queue.qsize()})")
        return True # Indicate success
    except queue.Full:
        logger.warning(f"Raw log content queue is full. Discarding newly fetched data for '{filename}'.")
        return False # Indicate data was not queued

# ==============================================================================
# Background Polling Threads
# ==============================================================================
# Dedicated threads that continuously call the fetch functions at specified intervals.

def poll_stats_loop():
    """Background thread loop for polling statistics data."""
    thread_name = threading.current_thread().name
    logger.info(f"Polling thread '{thread_name}' started for stats (Interval: {POLL_STATS_INTERVAL_SECONDS}s).")
    while True:
        start_ts = time.monotonic()
        try:
            logger.debug(f"[{thread_name}] Polling stats...")
            # The decorator handles authentication, errors, and injecting args
            fetch_stats_raw_data()
        except Exception as e:
            # Catch unexpected errors within the loop itself
            logger.error(f"[{thread_name}] Unhandled error in poll_stats_loop: {e}", exc_info=True)
            # Sleep longer after an error to avoid tight error loops
            time.sleep(POLL_STATS_INTERVAL_SECONDS * 2)
        # Calculate sleep time to maintain interval accuracy
        elapsed = time.monotonic() - start_ts
        sleep_time = max(0, POLL_STATS_INTERVAL_SECONDS - elapsed)
        logger.debug(f"[{thread_name}] Stats poll cycle took {elapsed:.3f}s. Sleeping for {sleep_time:.3f}s.")
        time.sleep(sleep_time)

def poll_queues_loop():
    """Background thread loop for polling queue data."""
    thread_name = threading.current_thread().name
    logger.info(f"Polling thread '{thread_name}' started for queues (Interval: {POLL_QUEUES_INTERVAL_SECONDS}s).")
    while True:
        start_ts = time.monotonic()
        try:
            logger.debug(f"[{thread_name}] Polling queues...")
            fetch_queues_raw_data()
        except Exception as e:
            logger.error(f"[{thread_name}] Unhandled error in poll_queues_loop: {e}", exc_info=True)
            time.sleep(POLL_QUEUES_INTERVAL_SECONDS * 2)
        elapsed = time.monotonic() - start_ts
        sleep_time = max(0, POLL_QUEUES_INTERVAL_SECONDS - elapsed)
        logger.debug(f"[{thread_name}] Queues poll cycle took {elapsed:.3f}s. Sleeping for {sleep_time:.3f}s.")
        time.sleep(sleep_time)

def poll_loglist_loop():
    """Background thread loop for polling the list of available log files."""
    thread_name = threading.current_thread().name
    logger.info(f"Polling thread '{thread_name}' started for log list (Interval: {POLL_LOGLIST_INTERVAL_SECONDS}s).")
    while True:
        start_ts = time.monotonic()
        try:
            logger.debug(f"[{thread_name}] Polling log list...")
            fetch_loglist_raw_data()
        except Exception as e:
            logger.error(f"[{thread_name}] Unhandled error in poll_loglist_loop: {e}", exc_info=True)
            time.sleep(POLL_LOGLIST_INTERVAL_SECONDS * 2)
        elapsed = time.monotonic() - start_ts
        sleep_time = max(0, POLL_LOGLIST_INTERVAL_SECONDS - elapsed)
        logger.debug(f"[{thread_name}] Log list poll cycle took {elapsed:.3f}s. Sleeping for {sleep_time:.3f}s.")
        time.sleep(sleep_time)

def poll_logcontent_loop():
    """
    Background thread loop for polling the *latest* log content.
    Only fetches if auto-refresh is enabled and a log file is selected.
    """
    thread_name = threading.current_thread().name
    logger.info(f"Polling thread '{thread_name}' started for log content (Interval: {POLL_LOGCONTENT_INTERVAL_SECONDS}s).")
    while True:
        start_ts = time.monotonic()
        filename = None
        auto_refresh_is_enabled = False

        # Check state briefly under lock
        with state.lock:
            filename = state.current_log_filename
            auto_refresh_is_enabled = state.log_auto_refresh_enabled

        # Fetch only if conditions are met
        if filename and auto_refresh_is_enabled:
            try:
                logger.debug(f"[{thread_name}] Polling latest log content for '{filename}' (auto-refresh enabled)...")
                # Only fetch *latest* in this loop (fetch_older=False)
                fetch_log_content_raw_data(filename=filename, fetch_older=False)
            except Exception as e:
                logger.error(f"[{thread_name}] Unhandled error in poll_logcontent_loop for '{filename}': {e}", exc_info=True)
                # Don't add extra sleep here, rely on the main interval calculation
        else:
            # Log reason for skipping
            reason = "no file selected" if not filename else "auto-refresh disabled"
            logger.debug(f"[{thread_name}] Log content polling skipped ({reason}).")

        # Maintain interval
        elapsed = time.monotonic() - start_ts
        sleep_time = max(0, POLL_LOGCONTENT_INTERVAL_SECONDS - elapsed)
        logger.debug(f"[{thread_name}] Log content poll cycle check took {elapsed:.3f}s. Sleeping for {sleep_time:.3f}s.")
        time.sleep(sleep_time)

# ==============================================================================
# Data Processing Thread
# ==============================================================================
# A dedicated thread that consumes raw data from the queues and updates the
# processed state in DashboardState.

def process_data_loop():
    """
    Background thread loop that continuously processes data from the raw data queues.
    """
    thread_name = threading.current_thread().name
    logger.info(f"Processing thread '{thread_name}' started.")
    consecutive_empty_cycles = 0
    max_empty_cycles_before_long_sleep = 10 # Sleep longer if nothing to process for a while

    while True:
        processed_something_this_cycle = False
        try:
            # --- Process Stats Queue ---
            while not state.raw_stats_queue.empty():
                try:
                    raw_stats = state.raw_stats_queue.get_nowait()
                    logger.debug(f"[{thread_name}] Processing item from raw_stats_queue...")
                    state.process_raw_stats(raw_stats)
                    state.raw_stats_queue.task_done() # Mark task as done for the queue
                    processed_something_this_cycle = True
                except queue.Empty:
                    logger.debug(f"[{thread_name}] raw_stats_queue became empty during processing.")
                    break # Exit inner loop if queue becomes empty concurrently
                except Exception as e:
                    logger.exception(f"[{thread_name}] Error processing item from stats queue.")
                    state.update_processing_error(f"Stats processing failed: {e}")
                    # Decide whether to break or continue processing other items

            # --- Process Queues Queue ---
            while not state.raw_queues_queue.empty():
                try:
                    raw_queues = state.raw_queues_queue.get_nowait()
                    logger.debug(f"[{thread_name}] Processing item from raw_queues_queue...")
                    state.process_raw_queues(raw_queues)
                    state.raw_queues_queue.task_done()
                    processed_something_this_cycle = True
                except queue.Empty:
                    logger.debug(f"[{thread_name}] raw_queues_queue became empty during processing.")
                    break
                except Exception as e:
                    logger.exception(f"[{thread_name}] Error processing item from queues queue.")
                    state.update_processing_error(f"Queues processing failed: {e}")

            # --- Process Log List Queue ---
            while not state.raw_loglist_queue.empty():
                try:
                    raw_loglist = state.raw_loglist_queue.get_nowait()
                    logger.debug(f"[{thread_name}] Processing item from raw_loglist_queue...")
                    state.process_raw_loglist(raw_loglist)
                    state.raw_loglist_queue.task_done()
                    processed_something_this_cycle = True
                except queue.Empty:
                    logger.debug(f"[{thread_name}] raw_loglist_queue became empty during processing.")
                    break
                except Exception as e:
                    logger.exception(f"[{thread_name}] Error processing item from loglist queue.")
                    state.update_processing_error(f"Loglist processing failed: {e}")

            # --- Process Log Content Queue ---
            while not state.raw_logcontent_queue.empty():
                try:
                    log_content_package = state.raw_logcontent_queue.get_nowait()
                    filename = log_content_package.get("filename", "unknown_file")
                    logger.debug(f"[{thread_name}] Processing item from raw_logcontent_queue for '{filename}'...")
                    state.process_raw_log_content(log_content_package)
                    state.raw_logcontent_queue.task_done()
                    processed_something_this_cycle = True
                except queue.Empty:
                    logger.debug(f"[{thread_name}] raw_logcontent_queue became empty during processing.")
                    break
                except Exception as e:
                    logger.exception(f"[{thread_name}] Error processing item from log content queue.")
                    state.update_processing_error(f"Log content processing failed: {e}")

        except Exception as e:
            # Catch unexpected errors in the main processing loop structure
            logger.error(f"[{thread_name}] Critical error in processing loop: {e}", exc_info=True)
            state.update_processing_error(f"Critical processing loop error: {e}")
            # Sleep longer after a major loop error to prevent rapid failures
            time.sleep(5)

        # --- Sleep Logic ---
        # Sleep briefly if nothing was processed to prevent 100% CPU usage when idle.
        # Sleep longer if queues have been empty for several cycles.
        if not processed_something_this_cycle:
            consecutive_empty_cycles += 1
            sleep_duration = 1.0 if consecutive_empty_cycles >= max_empty_cycles_before_long_sleep else 0.2
            # logger.debug(f"[{thread_name}] No data processed in this cycle ({consecutive_empty_cycles} consecutive empty). Sleeping for {sleep_duration}s.")
            time.sleep(sleep_duration)
        else:
            consecutive_empty_cycles = 0 # Reset counter if something was processed
            # Optionally sleep very briefly even if processing occurred, e.g., time.sleep(0.01)
            # This can yield control and prevent potential starvation of other threads,
            # but might slightly increase processing latency. Usually not needed with queue waits.
            pass

# ==============================================================================
# Manual Trigger Function (for UI actions like "Load Older Logs")
# ==============================================================================

def trigger_log_content_fetch(filename: str, fetch_older: bool):
    """
    Triggers a log content fetch operation (typically for 'Load Older' or initial load)
    by running the fetch function in a separate background thread.
    This prevents blocking the main processing loop or Flask request handlers.
    """
    thread_name = f"TriggerLogFetch-{filename[:15]}-{'Older' if fetch_older else 'Latest'}"
    logger.info(f"Dispatching background thread '{thread_name}' to fetch log content...")

    # Create and start a daemon thread to execute the fetch function
    fetch_thread = threading.Thread(
        target=fetch_log_content_raw_data, # Target the raw data fetch function
        args=(filename, fetch_older),      # Pass necessary arguments
        name=thread_name,
        daemon=True                        # Allow program exit even if this thread hangs
    )
    fetch_thread.start()
    logger.debug(f"Thread '{thread_name}' started.")


# ==============================================================================
# Flask Web Application Setup
# ==============================================================================
# Initialize the Flask app and configure CORS.

logger.info("Initializing Flask application...")
# Use the specified template folder
app = Flask(__name__, template_folder='dash-templates')

# Ensure Flask logs through our configured logger
app.logger.handlers = logger.handlers
app.logger.setLevel(logger.level)

# Enable Cross-Origin Resource Sharing (CORS) for API endpoints
# This allows the JavaScript frontend (potentially served from a different origin)
# to make requests to the Python backend API.
CORS(app, resources={r"/api/*": {"origins": "*"}}) # Allow all origins for API routes

logger.info("Flask app initialized with CORS enabled for /api/*.")


# ==============================================================================
# Flask Routes (HTML and API Endpoints)
# ==============================================================================

# --- Route to Serve HTML Dashboard ---
@app.route('/')
def serve_dashboard():
    """Serves the main dashboard HTML page using an external template file."""
    client_ip = request.remote_addr
    logger.info(f"Request received for dashboard page '/' from client: {client_ip}")
    try:
        # Prepare configuration dictionary to be passed to the template/JavaScript
        # This allows the frontend to know the API endpoints and settings.
        dashboard_config = {
            "API_DASHBOARD_DATA_URL": "/api/dashboard_data",
            "API_LOG_DATA_URL": "/api/log_data",
            "API_FETCH_OLDER_LOGS_URL": "/api/fetch_older_logs",
            "API_TOGGLE_LOG_REFRESH_URL": "/api/toggle_log_refresh",
            "POLLING_INTERVAL_MS": POLL_STATS_INTERVAL_SECONDS * 1000,
            "LOG_REFRESH_INTERVAL_MS": POLL_LOGCONTENT_INTERVAL_SECONDS * 1000,
            "MAX_CHART_HISTORY": MAX_CHART_HISTORY,
            "LOG_CHUNK_SIZE": LOG_CHUNK_SIZE,
            "FETCH_STATS_INTERVAL_SECONDS": POLL_STATS_INTERVAL_SECONDS, # Informational
            # Pass initial log refresh state to avoid UI flicker
            "LOG_AUTO_REFRESH_ENABLED_INIT": state.log_auto_refresh_enabled
        }
        # Convert config to a JSON string to embed safely in the HTML
        config_json_str = json.dumps(dashboard_config)
        logger.debug("Rendering template 'dash3-rc1.html' with config.")
        # Render the external HTML template file, passing the config JSON
        return render_template('dash3-rc1.html', config_json=config_json_str)
    except Exception as e:
        # Handle errors during template rendering
        logger.exception("Error rendering dashboard template 'dash3-rc1.html'")
        # Return a simple error page to the user
        return f"<h1>Internal Server Error</h1><p>Failed to render dashboard template: {e}</p>", 500

# --- API Endpoint for Main Dashboard Data ---
@app.route('/api/dashboard_data')
def get_dashboard_data():
    """API endpoint to provide the current processed state snapshot."""
    request_start_time = time.monotonic()
    logger.debug("Request received for /api/dashboard_data")
    try:
        # Get the snapshot from the thread-safe state object
        data_snapshot = state.get_snapshot_for_dashboard()
        response = jsonify(data_snapshot)
        duration = time.monotonic() - request_start_time
        logger.debug(f"/api/dashboard_data request processed successfully in {duration:.4f}s.")
        return response
    except Exception as e:
        logger.exception("Error occurred while serving /api/dashboard_data")
        # Return a JSON error response
        return jsonify({"error": "Failed to get dashboard data", "detail": str(e)}), 500

# --- API Endpoint for Current Log View Data ---
@app.route('/api/log_data')
def get_log_data():
    """API endpoint providing the current state of the log viewer data (lines, filename, etc.)."""
    request_start_time = time.monotonic()
    logger.debug("Request received for /api/log_data")
    try:
        # Get the log-specific snapshot from the state
        log_data_snapshot = state.get_log_data_for_request()
        response = jsonify(log_data_snapshot)
        duration = time.monotonic() - request_start_time
        logger.debug(f"/api/log_data request processed successfully in {duration:.4f}s.")
        return response
    except Exception as e:
        logger.exception("Error occurred while serving /api/log_data")
        return jsonify({"error": "Failed to get log data", "detail": str(e)}), 500

# --- API Endpoint to Trigger Fetching Older Logs ---
@app.route('/api/fetch_older_logs')
def get_older_logs():
    """API endpoint triggered by the UI to initiate fetching of older log entries."""
    request_start_time = time.monotonic()
    logger.debug("Request received for /api/fetch_older_logs")
    filename = None
    # Get the currently selected filename safely
    with state.lock:
        filename = state.current_log_filename

    if filename:
        logger.info(f"Received request to fetch older logs for: {filename}")
        # Trigger the background fetch using the dedicated function
        trigger_log_content_fetch(filename, fetch_older=True)
        logger.info(f"Dispatched background thread to fetch older logs for {filename}.")
        # Return the *current* log state immediately. UI will update when new data is processed.
        try:
            current_log_state = state.get_log_data_for_request()
            response = jsonify(current_log_state)
            duration = time.monotonic() - request_start_time
            logger.debug(f"/api/fetch_older_logs processed (triggered fetch) in {duration:.4f}s.")
            return response
        except Exception as e:
            logger.exception("Error getting current log state after triggering older fetch")
            return jsonify({"error": "Failed to get current log state after triggering fetch", "detail": str(e)}), 500
    else:
        # Handle case where no log file is currently selected
        logger.warning("Cannot fetch older logs: No log file currently selected by the user.")
        return jsonify({"error": "No log file currently selected"}), 400

# --- API Endpoint to Toggle Log Auto-Refresh ---
@app.route('/api/toggle_log_refresh', methods=['POST'])
def toggle_log_refresh():
    """API endpoint for the UI to enable/disable log content auto-refresh."""
    request_start_time = time.monotonic()
    logger.debug("Request received for /api/toggle_log_refresh")
    try:
        # Expecting JSON payload like {"enabled": true} or {"enabled": false}
        request_data = request.get_json()
        if request_data is None or 'enabled' not in request_data or not isinstance(request_data['enabled'], bool):
            logger.warning("Invalid request to toggle log refresh: Missing or invalid 'enabled' field.")
            return jsonify({"error": "Missing or invalid 'enabled' (boolean) field in request body"}), 400

        new_enabled_state = request_data['enabled']
        logger.info(f"Received request to set log auto-refresh to: {new_enabled_state}")
        # Update the state thread-safely
        state.set_log_auto_refresh(new_enabled_state)
        response = jsonify({"success": True, "enabled": new_enabled_state})
        duration = time.monotonic() - request_start_time
        logger.debug(f"/api/toggle_log_refresh processed successfully in {duration:.4f}s.")
        return response
    except Exception as e:
        logger.exception("Error occurred while processing /api/toggle_log_refresh")
        return jsonify({"error": "Failed to toggle log refresh state", "detail": str(e)}), 500

# ==============================================================================
# Main Execution Block
# ==============================================================================

if __name__ == '__main__':
    """
    Main entry point for the dashboard server script.
    Initializes state, performs initial data fetch, starts background threads,
    and launches the Flask web server.
    """
    logger.info("==============================================================")
    logger.info(" Starting BrokerDash Pro Server (Pipeline Model) ")
    logger.info("==============================================================")

    # --- Disable SSL Warnings for Local Dev ---
    is_local_api = "127.0.0.1" in API_BASE_URL or "localhost" in API_BASE_URL
    if is_local_api:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning("SSL certificate verification disabled for target API requests (running against local address).")
        except ImportError:
            logger.warning("urllib3 library not found, cannot disable SSL warnings.")
        except Exception as e:
            logger.warning(f"Could not disable urllib3 warnings: {e}")
    else:
         logger.info(f"SSL verification ENABLED for target API requests ({API_BASE_URL}).")


    # --- Perform Initial Data Fetch & Processing ---
    # Try to populate the state with some data *before* starting the web server
    # to avoid the UI showing empty state initially.
    logger.info("--- Starting Initial Data Fetch Sequence ---")
    initial_fetch_start_time = time.monotonic()
    try:
        # 1. Attempt Login if needed (sets token in state)
        if state.needs_login():
            logger.info("Initial login required...")
            login_to_api() # This function handles its own logging/errors

        # 2. Trigger initial raw data fetches (run synchronously here)
        # The decorator handles using the token set by login_to_api
        logger.info("Fetching initial stats...")
        fetch_stats_raw_data()
        logger.info("Fetching initial queues...")
        fetch_queues_raw_data()
        logger.info("Fetching initial log list...")
        fetch_loglist_raw_data()

        # 3. Allow a brief moment for fetches to potentially complete and populate queues
        time.sleep(0.5) # Small delay

        # 4. Run processing loop logic a few times to process initial data
        logger.info("Running initial processing iterations...")
        max_initial_processing_iterations = 3
        for i in range(max_initial_processing_iterations):
            logger.debug(f"Initial processing iteration {i+1}/{max_initial_processing_iterations}...")
            processed_in_iteration = False
            # Process stats
            while not state.raw_stats_queue.empty():
                try: state.process_raw_stats(state.raw_stats_queue.get_nowait()); state.raw_stats_queue.task_done(); processed_in_iteration=True
                except Exception as proc_e: logger.error(f"Error in initial stats processing: {proc_e}")
            # Process queues
            while not state.raw_queues_queue.empty():
                try: state.process_raw_queues(state.raw_queues_queue.get_nowait()); state.raw_queues_queue.task_done(); processed_in_iteration=True
                except Exception as proc_e: logger.error(f"Error in initial queues processing: {proc_e}")
            # Process log list
            while not state.raw_loglist_queue.empty():
                try: state.process_raw_loglist(state.raw_loglist_queue.get_nowait()); state.raw_loglist_queue.task_done(); processed_in_iteration=True
                except Exception as proc_e: logger.error(f"Error in initial loglist processing: {proc_e}")
            # Note: Initial log *content* is triggered by process_raw_loglist if needed

            if not processed_in_iteration:
                logger.debug("Initial processing queues empty, stopping initial iterations.")
                break # Stop if nothing was processed

        initial_fetch_duration = time.monotonic() - initial_fetch_start_time
        logger.info(f"--- Initial Data Fetch Sequence Completed in {initial_fetch_duration:.2f}s ---")

    except Exception as e:
        # Log critical errors during startup but attempt to continue
        logger.exception("!!! Critical error during initial data fetch/processing sequence !!!")
        logger.error("The dashboard may start with incomplete data. Background polling will attempt to recover.")


    # --- Start Background Threads ---
    logger.info("--- Starting Background Threads ---")
    threads = []
    thread_configs = [
        (poll_stats_loop, "StatsPoller"),
        (poll_queues_loop, "QueuesPoller"),
        (poll_loglist_loop, "LogListPoller"),
        (poll_logcontent_loop, "LogContentPoller"),
        (process_data_loop, "ProcessingThread"),
    ]

    for target_func, thread_name in thread_configs:
        thread = threading.Thread(target=target_func, name=thread_name, daemon=True)
        threads.append(thread)
        thread.start()
        logger.info(f"Thread '{thread_name}' started.")

    logger.info("--- All Background Threads Initiated ---")


    # --- Display Final Configuration ---
    logger.info(f" --- BrokerDash Pro Configuration Summary --- ");
    logger.info(f" Dashboard Port: {DASHBOARD_PORT}");
    logger.info(f" Target API URL: {API_BASE_URL}");
    logger.info(f" Target API User: {API_USERNAME}");
    logger.info(f" Verify Target API SSL: {not is_local_api}");
    logger.info(f" Template Folder: dash-templates");
    logger.info(f" Poll Intervals (s): Stats={POLL_STATS_INTERVAL_SECONDS}, Queues={POLL_QUEUES_INTERVAL_SECONDS}, LogList={POLL_LOGLIST_INTERVAL_SECONDS}, LogContent={POLL_LOGCONTENT_INTERVAL_SECONDS}")
    logger.info(f" Max History Points: {MAX_CHART_HISTORY}")
    logger.info(f" Log Chunk Size: {LOG_CHUNK_SIZE} lines")
    logger.info(f" Max Log Lines in Memory: {MAX_LOG_LINES_MEMORY}")
    logger.info(f" ----------------------------------------- ")


    # --- Start Flask Web Server ---
    logger.info(f"Starting dashboard web server on http://0.0.0.0:{DASHBOARD_PORT}...")
    try:
        # Prefer Waitress for a more production-suitable server
        try:
            from waitress import serve
            logger.info("Using Waitress WSGI server.")
            # Adjust threads as needed based on expected load
            serve(app, host='0.0.0.0', port=DASHBOARD_PORT, threads=16)
        except ImportError:
            # Fallback to Flask's built-in development server if Waitress isn't installed
            logger.warning("Waitress package not found. Falling back to Flask's development server.")
            logger.warning("Flask's development server is NOT recommended for production environments.")
            app.run(host='0.0.0.0', port=DASHBOARD_PORT, debug=False, use_reloader=False)

    except KeyboardInterrupt:
        # Handle graceful shutdown on Ctrl+C
        logger.info("Dashboard server stopped by user (KeyboardInterrupt).")
    except Exception as e:
        # Catch other potential errors during server startup or runtime
        logger.critical(f"Dashboard server failed unexpectedly: {e}", exc_info=True)
        logger.critical("Please check logs, configuration, network connectivity, and port availability.")
        # Optional: Add cleanup logic here if needed before exiting

    finally:
        # This block executes whether the server stopped gracefully or crashed
        logger.info("BrokerDash Pro server process exiting.")
        # Note: Daemon threads will exit automatically when the main thread exits.
        # If non-daemon threads were used, they would need explicit joining here.