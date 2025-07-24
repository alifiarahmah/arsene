#!/usr/bin/env python3
"""
ZAP Proxy HAR Capture Script
Opens browser with ZAP proxy, captures traffic, and exports HAR file
"""

import time
import json
import subprocess
import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from zapv2 import ZAPv2

class CaptureModule:
    def __init__(self, zap_port=8080, zap_host='127.0.0.1'):
        self.zap_port = zap_port
        self.zap_host = zap_host
        self.zap_url = f'http://{zap_host}:{zap_port}'
        self.zap = ZAPv2(proxies={'http': self.zap_url, 'https': self.zap_url})
        self.driver = None
        self.zap_process = None

    def start_zap_daemon(self):
        """Start ZAP in daemon mode"""
        print(f"Starting ZAP daemon on port {self.zap_port}...")
        try:
            # Start ZAP in daemon mode
            self.zap_process = subprocess.Popen([
                'zap.sh', '-daemon',
                '-port', str(self.zap_port),
                '-config', 'api.disablekey=true'
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Wait for ZAP to start
            max_attempts = 30
            for attempt in range(max_attempts):
                try:
                    response = requests.get(f'{self.zap_url}/JSON/core/view/version/')
                    if response.status_code == 200:
                        print("ZAP daemon started successfully")
                        return True
                except requests.exceptions.ConnectionError:
                    time.sleep(2)
                    continue

            print("Failed to start ZAP daemon")
            return False

        except FileNotFoundError:
            print("ZAP not found. Please ensure OWASP ZAP is installed and zap.sh is in PATH")
            return False

    def setup_browser(self):
        """Setup Chrome browser with ZAP proxy"""
        print("Setting up browser with ZAP proxy...")

        chrome_options = Options()
        chrome_options.add_argument(f'--proxy-server={self.zap_url}')
        chrome_options.add_argument('--ignore-certificate-errors')
        chrome_options.add_argument('--ignore-ssl-errors')
        chrome_options.add_argument('--allow-running-insecure-content')
        chrome_options.add_argument('--disable-web-security')

        try:
            self.driver = webdriver.Chrome(options=chrome_options)
            print("Browser started with ZAP proxy")
            return True
        except Exception as e:
            print(f"Failed to start browser: {e}")
            return False

    def start_capture(self, target_url=None):
        """Start traffic capture and open browser"""
        print("\n=== Starting Manual Exploration ===")
        print("Browser is now open and configured with ZAP proxy")

        if target_url:
            print(f"Navigating to: {target_url}")
            self.driver.get(target_url)

        print("\nInstructions:")
        print("1. Manually explore the target application")
        print("2. All HTTP/HTTPS traffic will be captured by ZAP")
        print("3. Press ENTER when you're done exploring to save HAR file")

        input("\nPress ENTER when finished exploring...")

    def export_har(self, output_file='captured_traffic.har'):
        """Export captured traffic as HAR file"""
        print(f"\nExporting traffic to {output_file}...")

        try:
            # Get all messages from ZAP history
            messages = self.zap.core.messages()

            if not messages:
                print("No traffic captured!")
                return False

            # Create HAR structure
            har_data = {
                "log": {
                    "version": "1.2",
                    "creator": {
                        "name": "ZAP HAR Capture Script",
                        "version": "1.0"
                    },
                    "entries": []
                }
            }

            # Convert ZAP messages to HAR format
            for msg_id in messages:
                try:
                    msg = self.zap.core.message(msg_id)

                    # Parse request
                    request_header = msg['requestHeader']
                    request_body = msg['requestBody']

                    # Parse response
                    response_header = msg['responseHeader']
                    response_body = msg['responseBody']

                    # Extract method and URL from request header
                    request_lines = request_header.split('\n')
                    if request_lines:
                        method_url_line = request_lines[0]
                        parts = method_url_line.split(' ')
                        if len(parts) >= 2:
                            method = parts[0]
                            url = parts[1]

                            # Create HAR entry
                            entry = {
                                "startedDateTime": time.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                                "time": int(msg.get('responseTime', 0)),
                                "request": {
                                    "method": method,
                                    "url": url,
                                    "httpVersion": "HTTP/1.1",
                                    "headers": self._parse_headers(request_header),
                                    "queryString": [],
                                    "postData": {
                                        "mimeType": "application/x-www-form-urlencoded",
                                        "text": request_body
                                    } if request_body else {},
                                    "headersSize": len(request_header),
                                    "bodySize": len(request_body)
                                },
                                "response": {
                                    "status": int(msg.get('responseCode', 200)),
                                    "statusText": "OK",
                                    "httpVersion": "HTTP/1.1",
                                    "headers": self._parse_headers(response_header),
                                    "content": {
                                        "size": len(response_body),
                                        "mimeType": "text/html",
                                        "text": response_body
                                    },
                                    "headersSize": len(response_header),
                                    "bodySize": len(response_body)
                                },
                                "cache": {},
                                "timings": {
                                    "send": 0,
                                    "wait": int(msg.get('responseTime', 0)),
                                    "receive": 0
                                }
                            }

                            har_data["log"]["entries"].append(entry)

                except Exception as e:
                    print(f"Error processing message {msg_id}: {e}")
                    continue

            # Save HAR file
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(har_data, f, indent=2, ensure_ascii=False)

            print(f"HAR file saved: {output_file}")
            print(f"Total entries captured: {len(har_data['log']['entries'])}")
            return True

        except Exception as e:
            print(f"Error exporting HAR: {e}")
            return False

    def _parse_headers(self, header_text):
        """Parse HTTP headers from text to list format"""
        headers = []
        if header_text:
            lines = header_text.split('\n')[1:]  # Skip first line (method/status)
            for line in lines:
                if ':' in line:
                    name, value = line.split(':', 1)
                    headers.append({
                        "name": name.strip(),
                        "value": value.strip()
                    })
        return headers

    def cleanup(self):
        """Clean up resources"""
        print("\nCleaning up...")

        if self.driver:
            self.driver.quit()
            print("Browser closed")

        if self.zap_process:
            self.zap_process.terminate()
            self.zap_process.wait()
            print("ZAP daemon stopped")

    def run(self, target_url=None, output_file='captured_traffic.har'):
        """Main execution flow"""
        try:
            # Start ZAP daemon
            if not self.start_zap_daemon():
                return False

            # Setup browser
            if not self.setup_browser():
                return False

            # Start capture
            self.start_capture(target_url)

            # Export HAR
            return self.export_har(output_file)

        except KeyboardInterrupt:
            print("\nCapture interrupted by user")
            return False
        except Exception as e:
            print(f"Error during capture: {e}")
            return False
        finally:
            self.cleanup()

def main():
    """Main function"""
    print("ZAP Proxy HAR Capture Tool")
    print("=" * 30)

    # Configuration
    target_url = input("Enter target URL (optional, press ENTER to skip): ").strip()
    output_file = input("Enter output HAR filename (default: captured_traffic.har): ").strip()

    if not target_url:
        target_url = None
    if not output_file:
        output_file = 'captured_traffic.har'

    # Run capture
    capture = CaptureModule()
    success = capture.run(target_url, output_file)

    if success:
        print(f"\n✓ HAR file successfully saved as: {output_file}")
    else:
        print("\n✗ HAR capture failed")

if __name__ == "__main__":
    main()