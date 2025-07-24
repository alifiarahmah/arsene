# aliptesis

first things first before local development
```sh
ssh -p 23870 root@ssh6.vast.ai  -L 8080:localhost:8080 -L 11434:localhost:11434
```

## List module

1. `capture_module`: Traffic capture & preprocessing
2. `parser_module`: Parse captured traffic, identify endpoints
3. `reasoning_module`: LLM reasoning, generate test cases/payloads
4. `vuln_analysis_module`: Execute test cases, analyze responses
5. `exploitation_module`: Attempt to exploit identified vulns
6. `reporting_module`: Aggregate result, create structured report

## Todo:

- [ ] `capture_module`

  - [ ] Integrate with ZAP CLI or custom proxy for HTTP/HTTPS capture
  - [ ] Export traffic to HAR format
  - [ ] (Optional) Preprocess HAR to remove external static resources
  - [ ] Store captured HAR in DataStore

- [x] `parser_module`

  - [x] Parse HAR file to structured JSON
  - [x] Filter and classify endpoints (exclude static/irrelevant)
  - [x] Extract parameters, headers, context for each endpoint

- [x] `reasoning_module`

  - [x] Design prompt template for LLM (test case generation)
  - [x] Integrate with local LLM for reasoning
  - [x] Generate test cases/payloads for each endpoint
  - [x] Output: endpoint + test case list (for vuln analysis)

- [ ] `vuln_analysis_module`

  - [ ] Execute generated test cases (HTTP requests, payload injection)
  - [ ] Integrate with tools (curl, sqlmap, XSStrike, SSRFmap)
  - [ ] Analyze responses for signs of vulnerability
  - [ ] Aggregate findings and evidence

- [ ] `exploitation_module`

  - [ ] Attempt PoC exploitation for confirmed/suspected vulns
  - [ ] Automate browser-based PoC (Selenium, if needed)
  - [ ] Collect and store exploitation evidence (req/res, screenshot)

- [ ] `reporting_module`
  - [ ] Aggregate results from analysis and exploitation
  - [ ] Generate structured report (text/HTML/PDF)
  - [ ] Include evidence, CVSS scoring, and recommendations
  - [ ] Store and/or export report to DataStore

## Requirements

- ZAP
  ```
  sudo apt update
  sudo apt install snapd
  sudo snap install zaproxy
  ```
-
