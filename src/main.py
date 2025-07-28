from capture import CaptureModule
from parser import ParserModule
from reasoning import ReasoningModule
from vuln_analysis import VulnerabilityAnalysisModule

def StartCaptureModule():
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
    CM = CaptureModule(START_URL, OUTPUT_FILE)
    CM.start_recording()

if __name__ == "__main__":
    # StartCaptureModule()

    filename = input('Enter filename (har/<name>.har): ')

    # ParserModule
    PM = ParserModule()
    endpoints = PM.parse_har_file(f'hars/{filename}.har')
    PM.export_to_json(endpoints, f'json/{filename}.json')
    print(f'Result saved as json/{filename}.json')

    # ReasoningModule
    RM = ReasoningModule()
    res = RM.analyze_endpoint('json/' + filename + '.json')
    print(res)
    RM.export_result(res, f'reasoning_result/{filename}.txt')
    print(f'Result saved as reasoning_result/{filename}.txt')

    # VulnAnalysisModule
    VA = VulnerabilityAnalysisModule()
    result = VA.read_reasoning_result(f'reasoning_result/{filename}.txt')

    # for every result, parse http requests
    for e in result:
        print(VA.parse_http_request(e['full_payload_with_curl']))