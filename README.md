# aliptesis

![](https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTmWazY73skM6JPdteLcK7-7d73LEPwVFCd2Q&s)

List module

1. `capture-module`: Traffic capture & Preprocessing
2. `reasoning-module`: LLM reasoning, identify potential vulns
3. `exploitation-module`: Attempt to exploit identified vulns
4. `reporting-module`: Aggregate result, create structured report (PDF)

Todo:

- [ ] `capture-module`
  - [x] ZAP
  - [ ] Selenium
  - [ ] Websocket
  - [ ] Playwright
- [ ] `reasoning-module`
  - [x] LLM
  - [ ] Wrapper
  - [ ] Clustering endpoints, state transitions
- [ ] `exploitation-module`
  - [ ] Prompts (ongoing) (make it continous/try another if fail)
  - [ ] Payload diversity & advanced testing (privesc dll)
  - [ ] Prioritization (prioritize critical over low-value ones)
- [ ] `reporting-module`
  - [ ] Evidence collection
  - [ ] Risk table (severity x likelihood)
  - [ ] PDF generation
- [ ] bikin pipeline semua
- [ ] OPTIONAL: web interface, tapi urgensinya apa?
