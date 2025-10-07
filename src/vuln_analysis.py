import requests
import json
import argparse

class VulnerabilityAnalysisModule:
    def read_tc(self, filepath):
        with open(filepath, 'r') as f:
            data = json.load(f)
        return data

    def do_vuln_analysis(self, filename):
        tcs = self.read_tc('reasoning_result/' + filename + '.json')
        for tc in tcs['test_cases']:
            r = self.make_request(tc)
        return r

    def make_request(self, tc):
        for payload_group in tc['payloads']: # benign/probe
            request_params = {
                'method': tc['method'],
                'url': tc['base_url'] + tc['endpoint']
            }
            # add header for every payload group
            request_header = {}
            for h in payload_group['header']:
                request_header[h['header_name']] = h['header_value']
            request_params['headers'] = request_header
            for payload in payload_group['payloads']:
                # add payload based on location
                location = payload['location']
                value = payload['value']
                if location == 'query':
                    request_params['url'] += value
                elif location == 'body':
                    request_params['data'] = value
                elif location == 'path':
                    request_params['url'] = tc['base_url'] + value
                elif location == 'header':
                    if 'headers' not in request_params:
                        request_params['headers'] = {}
                    key, val = value.split(':', 1)
                    request_params['headers'][key.strip()] = val.strip()
                elif location == 'cookie':
                    if 'cookies' not in request_params:
                        request_params['cookies'] = {}
                    key, val = value.split(':', 1)
                    request_params['cookies'][key.strip()] = val.strip()
            if payload_group.get('content_type'):
              if 'headers' not in request_params:
                  request_params['headers'] = {}
              request_params['headers']['Content-Type'] = payload_group['content_type']

            try:
                r = requests.request(**request_params)
                print(
                    f"TC: {tc['id']}, Tier: {payload_group['tier']}, "
                    f"URL: {request_params['url']}, Status: {r.status_code}"

                )
            except Exception as e:
                print(f"Error in {tc['id']}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Execute testcases from reasoning and verify')
    parser.add_argument('filename', help='Filename without .har extension (e.g., "example" for reasoning_result/example.har)')
    args = parser.parse_args()
    filename = args.filename

    VAM = VulnerabilityAnalysisModule()
    res = VAM.do_vuln_analysis(filename)