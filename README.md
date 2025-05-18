# CyberShield Phishing URL Detector

A Chrome extension for detecting phishing URLs using Google Safe Browsing, a local database, and voice feedback.

## Features
- Real-time URL analysis with Google Safe Browsing API.
- Local phishing URL database fallback.
- Voice feedback and JSON report export.
- Customizable settings.

## File Structure
- `index.html`: Popup UI.
- `style.css`: Styling.
- `app.js`: Logic and API integration.
- `phishing-urls.json`: Local phishing database.
- `manifest.json`: Extension manifest.
- `icons/`: Icon assets.

## Installation
1. Clone or download this repository.
2. Open `chrome://extensions` in Chrome.
3. Enable **Developer Mode**.
4. Click **Load unpacked** and select the extension folder.
5. Click the extension icon to use.

## Usage
1. Enter a URL in the input field.
2. Click **Analyze** to check for phishing.
3. View risk score, domain details, and results.
4. Export results as a JSON report.

## API Setup
1. Create a Google Cloud project at [console.cloud.google.com](https://console.cloud.google.com).
2. Enable the Safe Browsing API and generate an API key.
3. (Optional) Store the key in `chrome.storage` or replace `YOUR_GOOGLE_SAFE_BROWSING_API_KEY` in `app.js`.

## Publishing
- Zip the extension folder.
- Upload to the [Chrome Web Store](https://chrome.google.com/webstore) for free distribution.