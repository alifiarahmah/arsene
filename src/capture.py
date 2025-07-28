import json
import time
import os
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
import threading
import base64

class CaptureModule:
    def __init__(self, start_url, output_file="session.har"):
        self.start_url = start_url
        self.output_file = output_file
        self.driver = None
        self.har_data = {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "Capture Module",
                    "version": "2.0"
                },
                "entries": []
            }
        }
        self.recording = True
        self.request_data = {}  # Store request data by requestId

        # Ensure output directory exists
        os.makedirs(os.path.dirname(self.output_file) if os.path.dirname(self.output_file) else '.', exist_ok=True)

    def setup_driver(self):
        """Setup Chrome driver with CDP logging"""
        chrome_options = Options()
        chrome_options.add_argument("--enable-network-service-logging")
        chrome_options.add_argument("--log-level=0")
        chrome_options.add_argument("--disable-web-security")
        chrome_options.add_argument("--disable-features=VizDisplayCompositor")

        chrome_options.set_capability("goog:loggingPrefs", {"performance": "ALL"})

        self.driver = webdriver.Chrome(options=chrome_options)
        self.driver.execute_cdp_cmd('Network.enable', {})
        self.driver.execute_cdp_cmd('Runtime.enable', {})

    def parse_headers(self, headers_dict):
        """Convert headers dict to HAR format"""
        return [{"name": k, "value": v} for k, v in headers_dict.items()]

    def parse_query_string(self, url):
        """Extract query string parameters from URL"""
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        return [{"name": k, "value": v[0] if v else ""} for k, v in query_params.items()]

    def get_cookies(self):
        """Get cookies from browser"""
        try:
            cookies = self.driver.get_cookies()
            return [{"name": c["name"], "value": c["value"], "domain": c.get("domain", "")} for c in cookies]
        except:
            return []

    def monitor_network_events(self):
        """Monitor network events using CDP"""
        while self.recording:
            try:
                # Get network logs
                logs = self.driver.get_log('performance')

                for log in logs:
                    message = json.loads(log['message'])
                    method = message.get('message', {}).get('method', '')
                    params = message.get('message', {}).get('params', {})

                    if method == 'Network.requestWillBeSent':
                        self.handle_request_sent(params)
                    elif method == 'Network.responseReceived':
                        self.handle_response_received(params)
                    elif method == 'Network.loadingFinished':
                        self.handle_loading_finished(params)
                    elif method == 'Network.loadingFailed':
                        self.handle_loading_failed(params)

                time.sleep(0.5)  # Check twice per second

            except Exception as e:
                if self.recording:  # Only print if still recording
                    print(f"Network monitoring error: {e}")
                break

    def handle_request_sent(self, params):
        """Handle Network.requestWillBeSent event"""
        request_id = params.get('requestId')
        request = params.get('request', {})
        timestamp = params.get('timestamp', time.time())

        # Store request data
        self.request_data[request_id] = {
            'request': request,
            'timestamp': timestamp,
            'url': request.get('url', ''),
            'method': request.get('method', 'GET'),
            'headers': request.get('headers', {}),
            'postData': request.get('postData', ''),
            'startTime': timestamp
        }

        print(f"Request: {request.get('method', 'GET')} {request.get('url', '')}")

    def handle_response_received(self, params):
        """Handle Network.responseReceived event"""
        request_id = params.get('requestId')
        response = params.get('response', {})
        timestamp = params.get('timestamp', time.time())

        if request_id in self.request_data:
            self.request_data[request_id]['response'] = response
            self.request_data[request_id]['responseTime'] = timestamp

            print(f"Response: {response.get('status', 0)} {response.get('url', '')}")

    def handle_loading_finished(self, params):
        """Handle Network.loadingFinished event"""
        request_id = params.get('requestId')
        timestamp = params.get('timestamp', time.time())
        encoded_data_length = params.get('encodedDataLength', 0)

        if request_id in self.request_data:
            self.request_data[request_id]['finishTime'] = timestamp
            self.request_data[request_id]['encodedDataLength'] = encoded_data_length

            # Try to get response body
            try:
                response_body = self.driver.execute_cdp_cmd('Network.getResponseBody', {'requestId': request_id})
                self.request_data[request_id]['responseBody'] = response_body
            except:
                self.request_data[request_id]['responseBody'] = {'body': '', 'base64Encoded': False}

            # Create HAR entry
            self.create_har_entry(request_id)

    def handle_loading_failed(self, params):
        """Handle Network.loadingFailed event"""
        request_id = params.get('requestId')
        error_text = params.get('errorText', 'Unknown error')
        timestamp = params.get('timestamp', time.time())

        if request_id in self.request_data:
            self.request_data[request_id]['failed'] = True
            self.request_data[request_id]['errorText'] = error_text
            self.request_data[request_id]['finishTime'] = timestamp

            # Create HAR entry for failed request
            self.create_har_entry(request_id)

            print(f"Failed: {error_text} - {self.request_data[request_id].get('url', '')}")

    def create_har_entry(self, request_id):
        """Create HAR entry from collected request/response data"""
        if request_id not in self.request_data:
            return

        data = self.request_data[request_id]
        request = data.get('request', {})
        response = data.get('response', {})
        response_body = data.get('responseBody', {})

        # Calculate timings
        start_time = data.get('startTime', 0)
        response_time = data.get('responseTime', start_time)
        finish_time = data.get('finishTime', response_time)

        total_time = (finish_time - start_time) * 1000  # Convert to milliseconds
        wait_time = (response_time - start_time) * 1000
        receive_time = (finish_time - response_time) * 1000

        # Parse request body
        post_data = None
        if data.get('postData'):
            post_data = {
                "mimeType": request.get('headers', {}).get('content-type', 'application/octet-stream'),
                "text": data['postData']
            }

        # Parse response content
        content = {
            "size": len(response_body.get('body', '')),
            "mimeType": response.get('mimeType', 'text/html'),
            "text": response_body.get('body', '') if not response_body.get('base64Encoded', False) else '',
            "encoding": "base64" if response_body.get('base64Encoded', False) else None
        }

        if response_body.get('base64Encoded', False):
            content["text"] = response_body.get('body', '')

        # Create HAR entry
        entry = {
            "startedDateTime": datetime.fromtimestamp(start_time).isoformat() + "Z",
            "time": max(total_time, 0),
            "request": {
                "method": data.get('method', 'GET'),
                "url": data.get('url', ''),
                "httpVersion": "HTTP/1.1",
                "headers": self.parse_headers(data.get('headers', {})),
                "queryString": self.parse_query_string(data.get('url', '')),
                "cookies": self.get_cookies(),
                "headersSize": -1,
                "bodySize": len(data.get('postData', '')),
                "postData": post_data
            },
            "response": {
                "status": response.get('status', 0),
                "statusText": response.get('statusText', ''),
                "httpVersion": response.get('protocol', 'HTTP/1.1'),
                "headers": self.parse_headers(response.get('headers', {})),
                "cookies": [],
                "content": content,
                "redirectURL": response.get('headers', {}).get('location', ''),
                "headersSize": -1,
                "bodySize": data.get('encodedDataLength', 0)
            },
            "cache": {},
            "timings": {
                "blocked": -1,
                "dns": -1,
                "connect": -1,
                "send": 0,
                "wait": max(wait_time, 0),
                "receive": max(receive_time, 0),
                "ssl": -1
            }
        }

        # Remove postData if empty
        if not post_data:
            del entry["request"]["postData"]

        # Remove encoding if not base64
        if not content.get("encoding"):
            if "encoding" in content:
                del content["encoding"]

        self.har_data["log"]["entries"].append(entry)

        # Clean up stored data
        del self.request_data[request_id]

    def save_har_file(self):
        """Save the HAR data to file"""
        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(self.har_data, f, indent=2, ensure_ascii=False)
        print(f"HAR file saved: {self.output_file}")
        print(f"Total entries recorded: {len(self.har_data['log']['entries'])}")

    def start_recording(self):
        """Start the browser and begin recording"""
        try:
            print("Setting up browser with network monitoring...")
            self.setup_driver()

            print(f"Opening {self.start_url}")
            self.driver.get(self.start_url)

            # Start network monitoring in a separate thread
            monitor_thread = threading.Thread(target=self.monitor_network_events)
            monitor_thread.daemon = True
            monitor_thread.start()

            print("\n" + "="*60)
            print("🎯 Browser is now recording ALL network traffic!")
            print("📊 Capturing: URLs, headers, cookies, request/response bodies")
            print("🔍 Navigate to any URLs you want to record.")
            print("⏹️  Press Enter in this terminal to stop recording...")
            print("="*60 + "\n")

            # Wait for user input to stop
            input()

        except KeyboardInterrupt:
            print("\nRecording interrupted by user")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            self.stop_recording()

    def stop_recording(self):
        """Stop recording and cleanup"""
        print("\nStopping recording...")
        self.recording = False

        # Give some time for final network events
        time.sleep(2)

        if self.driver:
            self.driver.quit()

        self.save_har_file()
        print("Recording session completed!")

def main():
    print("🌐 Enhanced Browser Network Recorder")
    print("📡 Captures full HTTP request/response data")
    print("=" * 50)

    # Configuration
    START_URL = input("Enter the starting URL (or press Enter for https://google.com): ").strip()
    if not START_URL:
        START_URL = "https://google.com"
    elif not START_URL.startswith("http://") and not START_URL.startswith("https://"):
        START_URL = "https://" + START_URL

    OUTPUT_FILE = 'hars/' + input("Enter HAR output filename (or press Enter for 'hars/session.har'): ").strip() + '.har'
    if not OUTPUT_FILE:
        OUTPUT_FILE = "hars/session.har"

    # Start recording
    recorder = CaptureModule(START_URL, OUTPUT_FILE)
    recorder.start_recording()

if __name__ == "__main__":
    main()