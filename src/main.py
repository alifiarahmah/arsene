from capture import CaptureModule
from parser import ParserModule
from reasoning import ReasoningModule
from vuln_analysis import VulnerabilityAnalysisModule
import shlex
import subprocess

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
    print("==== [1/3] PARSING ====")
    PM = ParserModule()
    endpoints = PM.parse_har_file(f'hars/{filename}.har')
    PM.export_to_json(endpoints, f'parsed_hars/{filename}.json')
    print(f'Result saved as parsed_hars/{filename}.json')

    # ReasoningModule
    print("==== [2/3] REASONING ====")
    RM = ReasoningModule()
    res = RM.analyze_endpoint('parsed_hars/' + filename + '.json')
    RM.export_result(res, f'reasoning_result/{filename}.txt')
    print(f'Result saved as reasoning_result/{filename}.txt')

    # VulnAnalysisModule
    print("==== [3/3] VULN ANALYSIS ====")
    VA = VulnerabilityAnalysisModule()
    result = VA.read_reasoning_result(f'reasoning_result/{filename}.json')

    # for res in result: # type: ignore

    #     print(res['curl_baseline'])
    #     cmd = shlex.split(res['curl_baseline'].rstrip(','))
    #     result = subprocess.run(cmd, capture_output=True, text=True)
    #     print("STDOUT:", result.stdout)
    #     print("STDERR:", result.stderr)
    #     print("Return code:", result.returncode)
    #     print()

    #     print(res['curl_payload'])
    #     cmd = shlex.split(res['curl_payload'].rstrip(','))
    #     result = subprocess.run(cmd, capture_output=True, text=True)
    #     print("STDOUT:", result.stdout)
    #     print("STDERR:", result.stderr)
    #     print("Return code:", result.returncode)