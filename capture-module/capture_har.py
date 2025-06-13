import time
import json
import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
import os
import sys

class ZAPHarCapture:
    def __init__(self, zap_host='localhost', zap_port=8080):
        self.zap_host = zap_host
        self.zap_port = zap_port
        self.zap_url = f'http://{zap_host}:{zap_port}'
        self.driver = None

    def setup_chrome(self):
        """Setup Chrome with ZAP proxy"""
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--remote-debugging-port=9222')
        chrome_options.add_argument(f'--proxy-server=http://{self.zap_host}:{self.zap_port}')
        chrome_options.add_argument('--ignore-certificate-errors')
        chrome_options.add_argument('--ignore-ssl-errors')
        chrome_options.add_argument('--ignore-certificate-errors-spki-list')

        service = Service('/usr/bin/chromium-browser')
        self.driver = webdriver.Chrome(service=service, options=chrome_options)

    def wait_for_zap(self):
        """Wait for ZAP to be ready"""
        max_attempts = 30
        for attempt in range(max_attempts):
            try:
                response = requests.get(f'{self.zap_url}/JSON/core/view/version/')
                if response.status_code == 200:
                    print("ZAP is ready!")
                    return True
            except requests.exceptions.ConnectionError:
                print(f"Waiting for ZAP... (attempt {attempt + 1}/{max_attempts})")
                time.sleep(2)
        return False

    def browse_target(self, target_url, actions=None):
        """Browse target URL and perform actions"""
        print(f"Browsing to: {target_url}")
        self.driver.get(target_url)
        time.sleep(3)

        # Perform custom actions if provided
        if actions:
            for action in actions:
                try:
                    if action['type'] == 'click':
                        element = self.driver.find_element(action['by'], action['value'])
                        element.click()
                        time.sleep(2)
                    elif action['type'] == 'input':
                        element = self.driver.find_element(action['by'], action['value'])
                        element.send_keys(action['text'])
                        time.sleep(1)
                    elif action['type'] == 'wait':
                        time.sleep(action['seconds'])
                except Exception as e:
                    print(f"Action failed: {e}")

    def export_har(self, output_path='/workspace/output/capture.har'):
        """Export HAR file from ZAP"""
        try:
            response = requests.get(f'{self.zap_url}/OTHER/core/other/har/')
            if response.status_code == 200:
                with open(output_path, 'w') as f:
                    f.write(response.text)
                print(f"HAR file exported to: {output_path}")
                return True
            else:
                print(f"Failed to export HAR: {response.status_code}")
                return False
        except Exception as e:
            print(f"Error exporting HAR: {e}")
            return False

    def get_urls_from_zap(self):
        """Get all URLs discovered by ZAP"""
        try:
            response = requests.get(f'{self.zap_url}/JSON/core/view/urls/')
            if response.status_code == 200:
                data = response.json()
                return data.get('urls', [])
        except Exception as e:
            print(f"Error getting URLs: {e}")
        return []

    def cleanup(self):
        """Cleanup resources"""
        if self.driver:
            self.driver.quit()

def main():
    # Configuration
    target_url = os.getenv('TARGET_URL', 'http://testphp.vulnweb.com/')
    output_file = os.getenv('OUTPUT_FILE', '/workspace/output/capture.har')

    # Initialize capture
    capture = ZAPHarCapture()

    try:
        # Wait for ZAP to be ready
        if not capture.wait_for_zap():
            print("ZAP failed to start!")
            sys.exit(1)

        # Setup Chrome
        capture.setup_chrome()

        # Browse target (you can customize actions here)
        sample_actions = [
            {'type': 'wait', 'seconds': 2},
            # Add more actions as needed for your specific target
        ]

        capture.browse_target(target_url, sample_actions)

        # Get discovered URLs
        urls = capture.get_urls_from_zap()
        print(f"Discovered {len(urls)} URLs:")
        for url in urls[:10]:  # Show first 10
            print(f"  - {url}")

        # Export HAR
        if capture.export_har(output_file):
            print("HAR capture completed successfully!")
        else:
            print("HAR export failed!")
            sys.exit(1)

    except Exception as e:
        print(f"Error during capture: {e}")
        sys.exit(1)
    finally:
        capture.cleanup()

if __name__ == "__main__":
    main()