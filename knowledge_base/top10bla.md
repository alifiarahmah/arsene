OWASP Top 10 Business Logic Abuse

Business Logic Abuse refers to vulnerabilities arising from flaws in the design and implementation of an application's business processes. Unlike traditional security bugs, these abuses exploit the intended functionality in unintended ways, often bypassing security controls by manipulating the application's logic.

Source: https://owasp.org/www-project-top-10-for-business-logic-abuse/#

---

1. Action Limit Overrun

Attackers perform actions beyond the allowed limits, such as exceeding transaction counts, request rates, or usage quotas.

Root Causes:
- Lack of enforcement or improper enforcement of action limits.
- Missing or weak rate limiting and throttling mechanisms.

Examples:
- Submitting more transactions than allowed in a billing cycle.
- Excessive API calls bypassing rate limits.

Source: https://owasp.org/www-project-top-10-for-business-logic-abuse/docs/the-top-10/action-limit-overrun.html

---

2. Workflow Order Bypass

Attackers bypass or alter the intended sequence of steps in a business process.

Root Causes:
- Missing validation of workflow state transitions.
- Trusting client-side controls for workflow enforcement.

Examples:
- Skipping payment step but still receiving goods.
- Bypassing approval steps in a multi-step process.

Source: https://owasp.org/www-project-top-10-for-business-logic-abuse/docs/the-top-10/workflow-order-bypass.html

---

3. Object State Manipulations

Attackers manipulate the state of objects to cause unintended behavior.

Root Causes:
- Inadequate validation of object states.
- Failure to enforce state transitions securely.

Examples:
- Changing order status from "pending" to "shipped" without authorization.
- Modifying session or transaction states to escalate privileges.

Source: https://owasp.org/www-project-top-10-for-business-logic-abuse/docs/the-top-10/object-state-manipulations.html

---

4. Malicious Logic Loop

Attackers exploit loops or repeated logic to cause denial of service or resource exhaustion.

Root Causes:
- Lack of checks on loop iterations or recursion depth.
- Missing limits on repeated actions.

Examples:
- Triggering infinite loops in business logic causing system hang.
- Repeatedly submitting requests to exhaust resources.

Source: https://owasp.org/www-project-top-10-for-business-logic-abuse/docs/the-top-10/malicious-logic-loop.html

---

5. Artifact Lifetime Exploitation

Attackers exploit artifacts (e.g., tokens, sessions) beyond their intended lifetime.

Root Causes:
- Failure to expire or revoke artifacts properly.
- Reuse of stale or invalid artifacts.

Examples:
- Using expired session tokens to access resources.
- Replaying old transaction tokens.

Source: https://owasp.org/www-project-top-10-for-business-logic-abuse/docs/the-top-10/artifact-lifetime-exploitation.html

---

6. Missing Transition Validation

Attackers exploit missing validation on state or workflow transitions.

Root Causes:
- Lack of server-side validation for allowed transitions.
- Trusting client-side state management.

Examples:
- Moving an order directly from "new" to "completed" without processing.
- Skipping required intermediate states.

Source: https://owasp.org/www-project-top-10-for-business-logic-abuse/docs/the-top-10/missing-transition-validation.html

---

7. Resource Quota Violation

Attackers exceed resource quotas allocated to users or processes.

Root Causes:
- Missing or ineffective quota enforcement.
- Lack of monitoring and alerting on quota usage.

Examples:
- Consuming more storage or bandwidth than allowed.
- Exceeding API call quotas.

Source: https://owasp.org/www-project-top-10-for-business-logic-abuse/docs/the-top-10/resource-quota-violation.html

---

8. Internal State Disclosure

Attackers gain access to internal application state information that should be hidden.

Root Causes:
- Insufficient access controls on internal data.
- Leakage through error messages or debug information.

Examples:
- Viewing internal workflow states or flags.
- Accessing sensitive configuration or debug data.

Source: https://owasp.org/www-project-top-10-for-business-logic-abuse/docs/the-top-10/internal-state-disclosure.html

---

9. Broken Access Control

Attackers bypass access control mechanisms to perform unauthorized actions.

Root Causes:
- Improper or missing authorization checks.
- Flaws in role or permission management.

Examples:
- Accessing admin functions as a regular user.
- Modifying data without proper permissions.

Source: https://owasp.org/www-project-top-10-for-business-logic-abuse/docs/the-top-10/broken-access-control.html

---

10. Shadow Function Abuse

Attackers exploit hidden or undocumented functions in the application.

Root Causes:
- Presence of backdoor or debug functions left in production.
- Lack of proper access restrictions on hidden features.

Examples:
- Using undocumented API endpoints to bypass security.
- Exploiting debug commands to manipulate business logic.

Source: https://owasp.org/www-project-top-10-for-business-logic-abuse/docs/the-top-10/shadow-function-abuse.html

---

References

- OWASP Top 10 for Business Logic Abuse: https://owasp.org/www-project-top-10-for-business-logic-abuse/#
- Individual category pages linked above.
