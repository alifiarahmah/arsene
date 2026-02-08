from capture import CaptureModule
from parser import ParserModule
from reasoning import ReasoningModule
from vuln_analysis import VulnerabilityAnalysisModule

import os

def StartCaptureModule():
    # configuration
    START_URL = input("Enter the starting URL (or press Enter for https://google.com): ").strip()
    if not START_URL:
        START_URL = "https://google.com"
    elif not START_URL.startswith("http://") and not START_URL.startswith("https://"):
        START_URL = "https://" + START_URL

    output_name = input("Enter HAR output filename (without extension, default 'session'): ").strip() or 'session'
    OUTPUT_FILE = os.path.join('hars', f"{output_name}.har")

    # Ensure directories exist
    os.makedirs('hars', exist_ok=True)

    # start recording
    CM = CaptureModule(START_URL, OUTPUT_FILE)
    CM.start_recording()

if __name__ == "__main__":
    # StartCaptureModule()

    filename = input('Enter filename (without extension) in hars/<name>.har: ').strip()
    # ensure output dir exist
    os.makedirs('parsed_hars', exist_ok=True)
    os.makedirs('reasoning_result', exist_ok=True)

    # ParserModule
    print("==== [1/3] PARSING ====")
    PM = ParserModule()
    har_path = os.path.join('hars', f'{filename}.har')
    parsed_path = os.path.join('parsed_hars', f'{filename}.json')
    endpoints = PM.parse_har_file(har_path)
    PM.export_to_json(endpoints, parsed_path)
    print(f'Parsed endpoints saved as {parsed_path}')

    # ReasoningModule
    print("==== [2/3] REASONING ====")
    RM = ReasoningModule()
    reasoning_output_path = os.path.join('reasoning_result', f'{filename}.json')
    try:
        # run the full reasoning chain with context preservation
        res = RM.reasoning_chain(parsed_path)
        RM.export_result(res, reasoning_output_path)
        print(f'Result saved as {reasoning_output_path}')
    except Exception as e:
        print(f"Reasoning failed: {e}")
        raise

    # VulnAnalysisModule
    print("==== [3/3] VULN ANALYSIS ====")
    VA = VulnerabilityAnalysisModule()
    result = VA.read_reasoning_result(reasoning_output_path)
    # TODO: pass 'result' to VA to execute tests, apply heuristics, and produce exploit validation.