# Slack Messages Downloader

A simple, graphical user interface (GUI) application for downloading the message history of a Slack channel or direct message.

## Description

This application provides a user-friendly way to export conversations from Slack. It can fetch all messages, including threaded replies, from a specified channel and save them as a formatted text file. Users can optionally specify a date range to limit the exported messages. The application is designed to be straightforward, requiring only a Slack User API Key and the Target Channel ID to get started.

## Features

  * **Graphical User Interface:** Easy-to-use interface built with `tkinter`.
  * **Message Fetching:** Downloads the complete message history of a public channel, private channel, or direct message.
  * **Thread Support:** Fetches all replies within threads to ensure no part of the conversation is missed.
  * **Date Filtering:** Optionally specify a start and end date to export messages from a specific period.
  * **User-Friendly Output:** Saves the conversation in a human-readable plain text format.
  * **Message Preview:** Displays a preview of the most recent messages before downloading.
  * **Status Updates:** Provides real-time feedback on the fetching process.

## Prerequisites

Before you begin, ensure you have met the following requirements:

  * You have Python 3.x installed.
  * You have a Slack account and are a member of the workspace you want to export messages from.

## Installation

1.  Clone the repository or download the `slackd.py` file to your local machine.
2.  Install the required Python libraries using pip:
    ```bash
    pip install slack_sdk
    ```

## Usage

1.  **Get your Slack User API Key:**

      * You can obtain your User API Key (it starts with `xoxp-`) from the Slack API documentation or by creating a legacy token. Please be aware of the security implications of handling API tokens.

2.  **Get the Target Channel ID:**

      * For a public or private channel, you can find the Channel ID in the URL when you have the channel open in your browser. It will look something like `C0123456789`.
      * For a direct message, you may need to use the Slack API to find the conversation ID (usually starts with a `D`).

3.  **Run the application:**

    ```bash
    python slackd.py
    ```

4.  **Enter the required information in the GUI:**

      * **User API Key:** Your Slack `xoxp-` token.
      * **Target Channel ID:** The ID of the channel or conversation you want to export.
      * **Start Date (Optional):** The start of the date range in `DD-MM-YYYY` format.
      * **End Date (Optional):** The end of the date range in `DD-MM-YYYY` format.

5.  **Fetch and Download:**

      * Click the "Fetch Messages" button. The application will connect to Slack and download the messages. You will see progress updates in the status bar.
      * Once the messages are fetched, a preview will be shown.
      * Click the "Download Messages as Text (.txt)" button to save the conversation to a file.

## Disclaimer

This script is provided "as is", without warranty of any kind, express or implied. In no event shall the author be held liable for any claim, damages or other liability, arising from, out of or in connection with the software or the use or other dealings in the software.

**Author:** rsam@paloaltonetworks.com
**Release Version:** 0.2
