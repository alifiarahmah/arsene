import requests
import json

from schemas import TestCase

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
        print(tc.keys())
        # if tc['param_location'] == 'body':
        #     rb = requests.request(
        #         method=tc['method'],
        #         url=tc['base_url'] + tc['endpoint'],
        #         data=tc['payloads'][0]['value']
        #     )
        #     print('benign: ', rb.status_code)
        #     rp = requests.request(
        #         method=tc['method'],
        #         url=tc['base_url'] + tc['endpoint'],
        #         data=tc['payloads'][1]['value']
        #     )
        #     print('probe:', rp.status_code)
        # elif tc['param_location'] == 'path' or tc['param_location'] == 'query':
        #     rb = requests.request(
        #         method=tc['method'],
        #         url=tc['base_url'] + tc['payloads'][0]['value'],
        #     )
        #     print('benign:', rb.status_code)
        #     rp = requests.request(
        #         method=tc['method'],
        #         url=tc['base_url'] + tc['payloads'][0]['value'],
        #     )
        #     print('probe:', rp.status_code)
        # return r

if __name__ == "__main__":
    filename = 'juice_shop'
    VAM = VulnerabilityAnalysisModule()
    res = VAM.do_vuln_analysis(filename)
    # print(res)