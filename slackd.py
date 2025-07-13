# DISCLAIMER
# This script is provided "as is", without warranty of any kind, express or
# implied. In no event shall the author be held liable for any claim, damages or
# other liability, arising from, out of or in connection with the software or
# the use or other dealings in the software.
#
# Author: rsam@paloaltonetworks.com
# Release date: 13 Jul 2025
# Release version: 0.2
#
# --- Import necessary libraries ---
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import logging
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from typing import List, Dict, Optional
import json
from datetime import datetime
import threading
import queue
import ssl
import time

# --- Basic Configuration ---
# Configure basic logging to show informational messages
logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')
logger = logging.getLogger(__name__)

def create_text_from_messages(
    messages_to_export: List[Dict],
    channel_display_name_for_export: str,
    my_user_id_for_export: Optional[str],
    client_for_names: WebClient,
    user_info_cache: Dict,
    oldest_ts: Optional[float],
    latest_ts: Optional[float]
) -> str:
    """
    Formats a list of Slack message objects into a readable plain text string,
    performing a final filter to ensure all messages are within the date range.

    Args:
        messages_to_export: A list of Slack message dictionary objects.
        channel_display_name_for_export: The name of the channel for the header.
        my_user_id_for_export: The user ID of the person exporting, not currently used.
        client_for_names: An active Slack WebClient to fetch user info.
        user_info_cache: A cache dictionary to store user ID to display name mappings.
        oldest_ts: The Unix timestamp for the start date, for filtering.
        latest_ts: The Unix timestamp for the end date, for filtering.

    Returns:
        A single string containing the formatted conversation log.
    """
    
    # --- Final Filtering to remove any messages outside the date range ---
    final_messages = []
    if oldest_ts is not None or latest_ts is not None:
        for m in messages_to_export:
            try:
                msg_ts = float(m.get('ts', '0'))
                is_after_start = (oldest_ts is None) or (msg_ts >= oldest_ts)
                is_before_end = (latest_ts is None) or (msg_ts <= latest_ts)
                if is_after_start and is_before_end:
                    final_messages.append(m)
            except (ValueError, TypeError):
                # If timestamp is invalid, include it to be safe
                final_messages.append(m)
    else:
        # If no date range is specified, use all messages
        final_messages = messages_to_export

    lines = []
    # --- Header Information ---
    lines.append(f"Slack Conversation Log")
    lines.append(f"Channel/Conversation: {channel_display_name_for_export}")
    lines.append(f"Exported on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 40)
    lines.append("")

    # Sort messages chronologically (oldest first) based on their timestamp ('ts')
    chronological_messages = sorted(final_messages, key=lambda m: m.get('ts', '0'))

    def get_display_name_for_export(user_id: str) -> str:
        """Fetches a user's display name from cache or via API call."""
        # Check cache first to avoid redundant API calls
        if user_id in user_info_cache:
            return user_info_cache[user_id]
        try:
            # If not in cache, call the Slack API
            user_info_response = client_for_names.users_info(user=user_id)
            user = user_info_response.get("user", {})
            profile = user.get("profile", {})
            # Find the best available name from the user's profile
            name = profile.get("display_name_normalized") or \
                   profile.get("real_name_normalized") or \
                   profile.get("display_name") or \
                   profile.get("real_name") or \
                   user.get("name") or \
                   user_id
            # Cache the result for future use
            user_info_cache[user_id] = name
            return name
        except SlackApiError:
            # If API call fails, just use the user ID
            return user_id

    # --- Message Formatting Loop ---
    for msg in chronological_messages:
        sender_id = msg.get('user')
        display_name = "Unknown Sender"
        if sender_id:
            display_name = get_display_name_for_export(sender_id)
        # Handle messages from bots that may not have a user ID
        if 'bot_id' in msg and not sender_id:
            display_name = msg.get('username', f"Bot ({msg.get('bot_id')})")
        
        text_content = msg.get('text', '').replace('\\n', '\n')
        timestamp_str = msg.get('ts', '')
        
        # Check if the message is a reply in a thread to apply indentation
        is_reply = msg.get('thread_ts') and msg.get('thread_ts') != msg.get('ts')
        indent = "  " if is_reply else ""
        
        # Convert Unix timestamp to a human-readable format
        try:
            readable_time = datetime.fromtimestamp(float(timestamp_str)).strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError):
            readable_time = timestamp_str

        # Append the formatted message line
        lines.append(f"{indent}[{readable_time}] {display_name}:")
        
        # Indent the actual message text
        indented_text = "\n".join([f"{indent}{line}" for line in text_content.split('\n')])
        lines.append(indented_text)

        # If the message contains files, list their names
        if 'files' in msg:
            for file_info in msg['files']:
                lines.append(f"{indent}File: {file_info.get('name', 'Untitled File')}")
        
        # Add a separator for readability
        lines.append(f"{indent}{'-' * 20}")
    return "\n".join(lines)


class SlackDownloaderApp(tk.Tk):
    """
    Main application class for the Slack Messages Downloader GUI.
    Inherits from tkinter.Tk to create the main window.
    """
    def __init__(self):
        super().__init__()
        # --- Main Window Setup ---
        self.title("Slack Messages Downloader")
        self.geometry("1110x550") # Increased height for the new field

        # --- Instance Variables ---
        self.messages = None  # To store fetched messages
        self.channel_display_name_for_download = "" # To store the channel name for the output file
        self.processed_channel_id = "" # To store the channel ID being processed
        self.user_info_cache = {} # Cache for user ID -> display name mapping
        self.slack_token_for_processing = None # The token used for the current operation
        self.my_user_id_for_processing = "" # The user ID of the authenticated user
        self.client = None # The Slack WebClient instance
        self.ui_queue = queue.Queue() # Queue for communication between the background thread and the UI thread
        self.oldest_ts_for_export = None # To store start timestamp for final filtering
        self.latest_ts_for_export = None # To store end timestamp for final filtering

        # --- Main Frame ---
        main_frame = ttk.Frame(self, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # --- Controls Frame (Left Side) ---
        controls_frame = ttk.LabelFrame(main_frame, text="Input", padding="10")
        controls_frame.grid(row=0, column=0, sticky="ns", padx=(0, 10))
        main_frame.grid_rowconfigure(0, weight=1)

        # Slack Token input
        ttk.Label(controls_frame, text="User API Key (xoxp-...)").grid(row=0, column=0, sticky="w", pady=(0, 2))
        self.token_var = tk.StringVar()
        self.token_entry = ttk.Entry(controls_frame, textvariable=self.token_var, width=50)
        self.token_entry.grid(row=1, column=0, sticky="ew", pady=(0, 10))

        # Slack User ID (functionality commented out but variable kept to prevent errors)
        self.user_id_var = tk.StringVar()

        # Target Channel ID input
        ttk.Label(controls_frame, text="Target Channel ID").grid(row=2, column=0, sticky="w", pady=(0, 2))
        self.channel_id_var = tk.StringVar()
        self.channel_id_entry = ttk.Entry(controls_frame, textvariable=self.channel_id_var, width=50)
        self.channel_id_entry.grid(row=3, column=0, sticky="ew", pady=(0, 10))
        
        # Optional Start Date input
        ttk.Label(controls_frame, text="Start Date (DD-MM-YYYY) Leave blank for all messages").grid(row=4, column=0, sticky="w", pady=(0, 2))
        self.start_date_var = tk.StringVar()
        self.start_date_entry = ttk.Entry(controls_frame, textvariable=self.start_date_var, width=50)
        self.start_date_entry.grid(row=5, column=0, sticky="ew", pady=(0, 15))

        # Optional End Date input
        ttk.Label(controls_frame, text="End Date (DD-MM-YYYY) Leave blank for up to latest").grid(row=6, column=0, sticky="w", pady=(0, 2))
        self.end_date_var = tk.StringVar()
        self.end_date_entry = ttk.Entry(controls_frame, textvariable=self.end_date_var, width=50)
        self.end_date_entry.grid(row=7, column=0, sticky="ew", pady=(0, 15))

        # Fetch Messages button
        self.fetch_button = ttk.Button(controls_frame, text="Fetch Messages", command=self.start_fetch_thread)
        self.fetch_button.grid(row=8, column=0, ipady=5, pady=(0, 15))

        # Instructions text
        instructions_text = "Instructions\n\n1. Enter your Slack User API Key\n2. Enter Slack Target Channel ID\n3. Enter a Start/End Date (Optional)\n4. Click 'Fetch Messages'\n5. Download the .txt file"
        ttk.Label(controls_frame, text=instructions_text, justify=tk.LEFT).grid(row=9, column=0, sticky="w", pady=(20, 0))

        # Application Version text
        app_ver_text = "Release 0.2"
        ttk.Label(controls_frame, text=app_ver_text, justify=tk.LEFT).grid(row=10, column=0, sticky="w", pady=(20, 0))

        # --- Output Frame (Right Side) ---
        output_frame = ttk.Frame(main_frame, padding="10")
        output_frame.grid(row=0, column=1, sticky="nsew")
        main_frame.grid_columnconfigure(1, weight=1)

        # Status label
        self.status_var = tk.StringVar(value="Enter details and click 'Fetch Messages'.")
        self.status_label = ttk.Label(output_frame, textvariable=self.status_var, wraplength=450)
        self.status_label.grid(row=0, column=0, columnspan=2, sticky="w")

        # Progress bar
        self.progress_bar = ttk.Progressbar(output_frame, mode='determinate')
        self.progress_bar.grid(row=1, column=0, columnspan=2, sticky="ew", pady=10)

        # Download button
        self.download_button = ttk.Button(output_frame, text="Download Messages as Text (.txt)", command=self.save_file, state=tk.DISABLED)
        self.download_button.grid(row=2, column=0, sticky="w", pady=(10, 10))

        # Message Preview area
        ttk.Label(output_frame, text="Message Preview", font="-weight bold").grid(row=3, column=0, sticky="w", pady=(10, 5))
        self.preview_text = tk.Text(output_frame, height=20, width=80, state=tk.DISABLED, wrap=tk.WORD, bg=self.cget('bg'), relief=tk.FLAT)
        self.preview_text.grid(row=4, column=0, columnspan=2, sticky="nsew")
        output_frame.grid_rowconfigure(4, weight=1)

        # Configure tags for styling text in the preview area
        self.preview_text.tag_configure("info", foreground="gray", font="-size 10")
        self.preview_text.tag_configure("name", font="-weight bold")
        self.preview_text.tag_configure("content", lmargin1=10, lmargin2=10)
        self.preview_text.tag_configure("reply_content", lmargin1=25, lmargin2=25, foreground="#444")

        # Start the UI queue processor
        self.process_ui_queue()

    def update_status(self, text, color="black"):
        """Updates the status label with new text and color."""
        self.status_var.set(text)
        self.status_label.config(foreground=color)

    def process_ui_queue(self):
        """
        Processes messages from the background thread to update the UI.
        This runs continuously in the main UI thread.
        """
        try:
            # Process all pending messages in the queue
            while True:
                msg = self.ui_queue.get_nowait()
                msg_type = msg.get("type")
                if msg_type == "status": self.update_status(msg.get("text"), msg.get("color", "black"))
                elif msg_type == "progress": self.progress_bar['value'] = msg.get("value")
                elif msg_type == "preview": self.update_preview(msg.get("messages"))
                elif msg_type == "state":
                    self.fetch_button['state'] = msg.get("fetch_button", tk.NORMAL)
                    self.download_button['state'] = msg.get("download_button", tk.DISABLED)
                elif msg_type == "clear":
                    self.preview_text.config(state=tk.NORMAL)
                    self.preview_text.delete("1.0", tk.END)
                    self.preview_text.config(state=tk.DISABLED)
        except queue.Empty:
            # If the queue is empty, do nothing
            pass
        finally:
            # Schedule this method to run again after 100ms
            self.after(100, self.process_ui_queue)

    def start_fetch_thread(self):
        """
        Validates user input and starts the background thread for fetching messages.
        """
        token = self.token_var.get().strip()
        channel_id = self.channel_id_var.get().strip()
        user_id = self.user_id_var.get().strip()
        start_date = self.start_date_var.get().strip()
        end_date = self.end_date_var.get().strip()
        
        # Basic input validation
        if not token or not channel_id:
            messagebox.showerror("Input Error", "Slack User Token and Target Channel ID are required.")
            return
            
        # Validate and parse the optional start date
        oldest_ts = None
        if start_date:
            try:
                # Convert DD-MM-YYYY string to a Unix timestamp
                dt_object = datetime.strptime(start_date, "%d-%m-%Y")
                oldest_ts = dt_object.timestamp()
            except ValueError:
                messagebox.showerror("Input Error", "Invalid Start Date format. Please use DD-MM-YYYY.")
                return

        # Validate and parse the optional end date
        latest_ts = None
        if end_date:
            try:
                # Convert DD-MM-YYYY string to a Unix timestamp for the end of that day
                dt_object = datetime.strptime(f"{end_date} 23:59:59", "%d-%m-%Y %H:%M:%S")
                latest_ts = dt_object.timestamp()
            except ValueError:
                messagebox.showerror("Input Error", "Invalid End Date format. Please use DD-MM-YYYY.")
                return

        # Store timestamps for final filtering
        self.oldest_ts_for_export = oldest_ts
        self.latest_ts_for_export = latest_ts

        # Disable buttons and reset UI elements before starting
        self.fetch_button['state'] = tk.DISABLED
        self.download_button['state'] = tk.DISABLED
        self.messages = None
        self.ui_queue.put({"type": "clear"})
        self.progress_bar['value'] = 0
        
        # Start the fetching process in a separate thread to keep the UI responsive
        threading.Thread(target=self.fetch_worker, args=(token, channel_id, user_id, oldest_ts, latest_ts), daemon=True).start()

    def fetch_worker(self, token: str, channel_id: str, user_id: str, oldest_timestamp: Optional[float], latest_timestamp: Optional[float]):
        """
        The main worker function that runs in a background thread.
        It handles all Slack API interactions for fetching messages and user info.
        """
        try:
            # Reset caches and variables for the new operation
            self.user_info_cache = {}
            self.my_user_id_for_processing = user_id
            self.slack_token_for_processing = token
            self.processed_channel_id = channel_id
            self.ui_queue.put({"type": "status", "text": "Connecting to Slack...", "color": "blue"})

            # Create a Slack client, disabling SSL certificate verification
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname, ssl_context.verify_mode = False, ssl.CERT_NONE
            self.client = WebClient(token=token, ssl=ssl_context)

            # Test authentication to verify the token
            auth_response = self.client.auth_test()
            actual_user_id, user_name = auth_response.get("user_id"), auth_response.get("user")
            self.ui_queue.put({"type": "status", "text": f"Token is valid. Authenticated as: {user_name} ({actual_user_id})", "color": "green"})

            effective_my_id = user_id if user_id else actual_user_id
            if effective_my_id:
                self.user_info_cache[effective_my_id] = f"You ({effective_my_id})"

            # Get the display name of the channel/conversation
            self.channel_display_name_for_download = self._get_channel_display_name(channel_id, effective_my_id)

            # Fetch all messages from the specified channel
            fetched_messages = self._fetch_all_messages_from_channel(
                channel_id,
                oldest_timestamp=str(oldest_timestamp) if oldest_timestamp else None,
                latest_timestamp=str(latest_timestamp) if latest_timestamp else None
            )

            # --- Process the fetched messages ---
            if fetched_messages:
                self.messages = fetched_messages
                
                # --- Pre-cache all user information in the background thread ---
                self.ui_queue.put({"type": "status", "text": "Caching user information...", "color": "blue"})
                all_user_ids = {msg.get('user') for msg in fetched_messages if msg.get('user')}
                
                if all_user_ids:
                    total_users = len(all_user_ids)
                    for i, user_id_to_cache in enumerate(all_user_ids):
                        self._get_user_display_name(user_id_to_cache) # This populates the cache
                        progress = ((i + 1) / total_users) * 100
                        self.ui_queue.put({"type": "progress", "value": progress})

                # Send final success status and data to the UI thread
                self.ui_queue.put({"type": "status", "text": f"Success! Total messages fetched: {len(fetched_messages)}", "color": "green"})
                self.ui_queue.put({"type": "preview", "messages": fetched_messages})
                self.ui_queue.put({"type": "state", "fetch_button": tk.NORMAL, "download_button": tk.NORMAL})
            else:
                # Handle case where no messages are found
                message = f"No messages found in {self.channel_display_name_for_download}"
                if oldest_timestamp or latest_timestamp:
                    message += " for the specified date range."
                self.ui_queue.put({"type": "status", "text": message, "color": "orange"})
                self.ui_queue.put({"type": "state", "fetch_button": tk.NORMAL, "download_button": tk.DISABLED})
        # --- Error Handling ---
        except SlackApiError as e:
            error_msg = f"Slack API Error: {e.response['error']}. Needed scope: {e.response.get('needed', 'N/A')}"
            self.ui_queue.put({"type": "status", "text": error_msg, "color": "red"})
            self.ui_queue.put({"type": "state", "fetch_button": tk.NORMAL, "download_button": tk.DISABLED})
        except Exception as e:
            self.ui_queue.put({"type": "status", "text": f"An unexpected error occurred: {e}", "color": "red"})
            self.ui_queue.put({"type": "state", "fetch_button": tk.NORMAL, "download_button": tk.DISABLED})

    def _get_user_display_name(self, user_id: str) -> str:
        """Helper to get a user's display name, using a cache and handling rate limits."""
        if user_id in self.user_info_cache:
            return self.user_info_cache[user_id]
        
        while True:
            try:
                user_info_response = self.client.users_info(user=user_id)
                user = user_info_response.get("user", {})
                profile = user.get("profile", {})
                name = profile.get("display_name_normalized") or profile.get("real_name_normalized") or profile.get("display_name") or profile.get("real_name") or user.get("name") or user_id
                self.user_info_cache[user_id] = name
                return name
            except SlackApiError as e:
                if e.response["error"] == "ratelimited":
                    retry_after = int(e.response.headers.get('Retry-After', 1))
                    self.ui_queue.put({"type": "status", "text": f"Rate limited on user info. Pausing for {retry_after}s...", "color": "orange"})
                    time.sleep(retry_after)
                    continue # Retry the request
                else:
                    logger.warning(f"Could not fetch user info for {user_id}: {e.response['error']}")
                    return user_id # Give up on this user and return the ID

    def _get_channel_display_name(self, channel_id: str, self_user_id: Optional[str]) -> str:
        """Helper to get the name of a conversation (channel, DM, group)."""
        try:
            response = self.client.conversations_info(channel=channel_id)
            if response.get("ok"):
                channel_info = response.get("channel", {})
                if channel_info.get("is_im"): # If it's a Direct Message
                    return self._get_user_display_name(channel_info.get("user"))
                name = channel_info.get("name_normalized") or channel_info.get("name")
                if name:
                    if channel_info.get("is_channel"): return f"Channel: #{name}"
                    elif channel_info.get("is_group"): return f"Group: {name}"
                    return name
        except SlackApiError as e:
            logger.warning(f"Could not get channel info for {channel_id}: {e.response['error']}")
        return f"Conversation in Channel {channel_id}"

    def _fetch_all_messages_from_channel(self, channel_id: str, oldest_timestamp: Optional[str] = None, latest_timestamp: Optional[str] = None) -> List[Dict]:
        """Fetches all messages and thread replies from a given channel, handling rate limits."""
        all_messages_dict = {}

        self.ui_queue.put({"type": "status", "text": "Fetching main channel messages..."})
        page_count = 0
        cursor = None
        # --- Fetch main channel messages (paginated) ---
        while True:
            page_count += 1
            self.ui_queue.put({"type": "progress", "value": (page_count * 5) % 100})
            
            try:
                response = self.client.conversations_history(
                    channel=channel_id,
                    limit=200, # Max limit per page
                    cursor=cursor,
                    oldest=oldest_timestamp, # Apply start date filter
                    latest=latest_timestamp  # Apply end date filter
                )
                messages = response.get("messages", [])
                for msg in messages:
                    all_messages_dict[msg['ts']] = msg
                # Stop if there are no more pages
                if not response.get("has_more"):
                    break
                cursor = response.get("response_metadata", {}).get("next_cursor")
                
            except SlackApiError as e:
                if e.response["error"] == "ratelimited":
                    retry_after = int(e.response.headers.get('Retry-After', 1))
                    self.ui_queue.put({"type": "status", "text": f"Rate limited. Pausing for {retry_after} seconds...", "color": "orange"})
                    time.sleep(retry_after)
                    continue # Retry the same page
                else:
                    raise # Re-raise other API errors

        # --- Fetch replies for all threads found ---
        thread_timestamps = {msg.get('thread_ts') for msg in all_messages_dict.values() if msg.get('thread_ts')}

        if thread_timestamps:
            self.ui_queue.put({"type": "status", "text": f"Found {len(thread_timestamps)} threads. Fetching replies..."})
            thread_count = len(thread_timestamps)
            for i, ts in enumerate(thread_timestamps):
                self.ui_queue.put({"type": "progress", "value": (i / thread_count) * 100})
                cursor = None
                # Paginate through replies for each thread
                while True:
                    try:
                        response = self.client.conversations_replies(
                            channel=channel_id, 
                            ts=ts, 
                            limit=200, 
                            cursor=cursor,
                            oldest=oldest_timestamp, # Apply start date filter to replies
                            latest=latest_timestamp  # Apply end date filter to replies
                        )
                        messages = response.get("messages", [])
                        for msg in messages:
                            all_messages_dict[msg['ts']] = msg
                        if not response.get("has_more"):
                            break
                        cursor = response.get("response_metadata", {}).get("next_cursor")

                    except SlackApiError as e:
                        if e.response["error"] == "ratelimited":
                            retry_after = int(e.response.headers.get('Retry-After', 1))
                            self.ui_queue.put({"type": "status", "text": f"Rate limited. Pausing for {retry_after} seconds...", "color": "orange"})
                            time.sleep(retry_after)
                            continue # Retry the same page of replies
                        else:
                            raise # Re-raise other API errors


        self.ui_queue.put({"type": "progress", "value": 100})
        # Return a list of all messages, sorted with newest first
        return sorted(all_messages_dict.values(), key=lambda m: m.get('ts', '0'), reverse=True)

    def update_preview(self, messages: List[Dict]):
        """Updates the text preview box with the first few messages."""
        self.preview_text.config(state=tk.NORMAL) # Enable writing
        self.preview_text.delete("1.0", tk.END) # Clear previous content
        # Show the 5 most recent messages
        preview_messages = messages[:5]
        
        for msg in reversed(preview_messages): # Reverse to show oldest of the preview first
            sender_id = msg.get('user')
            display_name = "Unknown Sender"
            if sender_id:
                display_name = self._get_user_display_name(sender_id)
            if 'bot_id' in msg and not sender_id:
                display_name = msg.get('username', f"Bot ({msg.get('bot_id')})")
            
            text = msg.get('text', '')
            ts = msg.get('ts', '')
            is_reply = msg.get('thread_ts') and msg.get('thread_ts') != msg.get('ts')
            tag = "reply_content" if is_reply else "content"
            
            try:
                readable_time = datetime.fromtimestamp(float(ts)).strftime('%Y-%m-%d %H:%M:%S') if ts else "No Timestamp"
            except:
                readable_time = ts
                
            # Insert the formatted preview text using the configured tags
            self.preview_text.insert(tk.END, f"{readable_time} ", "info")
            self.preview_text.insert(tk.END, f"{display_name}:\n", "name")
            self.preview_text.insert(tk.END, f"{text[:300]}{'...' if len(text) > 300 else ''}\n\n", tag)
            
        self.preview_text.config(state=tk.DISABLED) # Disable writing

    def save_file(self):
        """
        Saves the fetched messages to a .txt file.
        Opens a file dialog to ask the user for the save location.
        """
        if not self.messages:
            messagebox.showwarning("No Data", "No messages to save.")
            return
        try:
            # Generate the full text content from the messages, passing the date range for final filtering
            text_content = create_text_from_messages(
                self.messages, 
                self.channel_display_name_for_download, 
                self.my_user_id_for_processing, 
                self.client, 
                self.user_info_cache,
                self.oldest_ts_for_export,
                self.latest_ts_for_export
            )
            # Create a default filename based on the channel name and ID
            channel_name_part = "".join(c for c in str(self.channel_display_name_for_download) if c.isalnum() or c in (' ', '_')).rstrip().replace(' ', '_')
            default_filename = f"slack_log_{self.processed_channel_id}_{channel_name_part}.txt"
            # Open the 'Save As' dialog
            filepath = filedialog.asksaveasfilename(initialfile=default_filename, defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
            if filepath:
                # Write the content to the selected file
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(text_content)
                messagebox.showinfo("Success", f"File saved successfully to:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Error Saving File", f"An error occurred: {e}")

# --- Application Entry Point ---
if __name__ == "__main__":
    # Create an instance of the app and run the main loop
    app = SlackDownloaderApp()
    app.mainloop()
