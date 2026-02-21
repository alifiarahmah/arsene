Business Logic Knowledge Base

General Characteristics of Business Logic Flaws

Core Idea:
- Business logic flaws arise when the implemented workflow, rules, or constraints can be bypassed, reordered, or abused while still using "legitimate" functionality.
- These flaws are highly application-specific and are usually not detectable by generic vulnerability scanners.

Key Properties:
- Require understanding of the intended workflow and its states.
- Often involve multi-step processes where skipping, repeating, or altering steps leads to unintended state transitions or benefits.
- Exploits typically look like "valid" requests but in an invalid context or order.

Pattern 1 – Business Logic Data Validation

WSTG-BUSL-01 – maps closely to Object State Manipulations (BLA3) and Missing Transition Validation (BLA6), partially to Internal State Disclosure (BLA8)

Name: Business Logic Data Validation

Short Description:
The application accepts data that is syntactically valid but logically inconsistent with business rules, or based on stale / incorrect state from other systems.

Relevant BL Abuse Types:
- BLA3 – Object State Manipulations: manipulating business objects into states that should not be reachable (e.g., forcing "out-of-stock" flows, changing routing of orders).
- BLA6 – Missing Transition Validation: accepting transitions that violate business constraints because data/state is not revalidated.
- BLA8 – Internal State Disclosure (indirectly): poor validation across system boundaries can expose internal assumptions about account balances, stock levels, etc.

Business Rules (Expected Behavior):
- All critical business data must be validated not only at the client but also on the server and across system boundaries.
- Decisions should be based on up-to-date, consistent state (e.g., inventory, credit limits, account status), not on stale snapshots that can be abused.
- Inputs must be checked against business constraints (e.g., stock availability, partner agreements, credit rules), not just format/length/type checks.

Typical Violations / Examples:
- Forcing an order down the "out-of-stock → partner drop-ship" path when the item is actually in stock, to abuse partner billing or logistics.
- Abusing nightly-synced financial systems: spending against yesterday's balance or exploiting time gaps in credit updates.
- Triggering external systems (partners, warehouses) with requests that appear consistent syntactically but bypass internal checks about authorization, stock, or payment.

HTTP / Traffic Indicators:
Requests that:
- Override or contradict server-side derived values (e.g., price, stock source, routing flags).
- Cause orders or operations to be sent to a partner/secondary system without matching in-app preconditions (e.g., no corresponding payment confirmation in the sequence).
- Rely on obviously stale data in multi-step flows (e.g., credit decisions based purely on an initial snapshot despite significant subsequent activity).

Test / Detection Heuristics (for LLM over HAR):
Look for sequences where:
- A single initial validation step is followed by multiple actions that rely on that step's data, without revalidation closer to the final state change.
- External calls (to partner endpoints, alternate fulfillment paths) are triggered even when previous steps suggest the normal path should be used.

Flag when a user is able to:
- Complete operations with logically invalid parameters (e.g., ordering non-existent SKU, using negative or unrealistic quantities) without rejection.

Pattern 2 – Ability to Forge Requests

WSTG-BUSL-02 – strongly related to Shadow Function Abuse (BLA10) and Broken Access Control (BLA9); can support BLA3/BLA6 when forged requests move objects across states

Name: Ability to Forge or Manipulate Business Requests

Short Description:
The attacker bypasses the normal GUI/workflow and directly crafts HTTP requests (via proxy or scripts) that manipulate hidden parameters, debug options, or undocumented endpoints to subvert business logic.

Relevant BL Abuse Types:
- BLA10 – Shadow Function Abuse: invoking hidden/undocumented features (debug flags, test-only controls, "Easter eggs") that change scoring, pricing, or access.
- BLA9 – Broken Access Control: using predictable identifiers or hidden flags to access or modify resources/functions beyond the intended role.
- BLA3/BLA6: forging requests that jump objects into states not achievable through the official UI sequence.

Business Rules (Expected Behavior):
- Only transitions triggered via the legitimate workflow, with correct preconditions and proper authorization, should be accepted.
- Hidden fields, flags, and developer/testing features must not be trusted as secure controls; they require server-side validation and strong access control.
- Predictable IDs or flags must not be sufficient to unlock discounts, debug views, or higher game levels.

Typical Violations / Examples:
- Reusing a single-use discount or "one-time" benefit multiple times by flipping a hidden discount_applied flag in repeated forged POST requests.
- Enabling debugging or internal testing modes (e.g., high-score multipliers, teleportation in games, fast-level progress) via hidden parameters left in production.
- Toggling flags that indicate whether certain preconditions were satisfied (e.g., KYC done, payment completed) without having performed those steps.

HTTP / Traffic Indicators:
Requests containing:
- Hidden or non-UI parameters like debug, mode, isDiscountApplied, isVerified, dev_flag being switched between values not available in UI.
- Repeated submissions of the same discount/promo flag across multiple checkouts.
- Access to endpoints or parameters that never appear in "normal" user flows but are used in "abusive" sequences (shadow APIs).

Sequences where:
- A later request claims a step has happened (e.g., paymentStatus=SUCCESS) without any earlier evidence in the HAR of that step.

Test / Detection Heuristics (LLM over HAR):
Compare "normal" traces vs suspicious traces to detect:
- New parameters introduced only in suspicious traces.
- Values toggled in ways not observable from GUI-driven flows.

Flag:
- Use of parameters that look like role switches, debug options, or "on/off" gates controlling discounts or access.

Pattern 3 – Integrity Checks

WSTG-BUSL-03 – maps well to Object State Manipulations (BLA3), Broken Access Control (BLA9), some Internal State Disclosure (BLA8)

Name: Insufficient Business Logic Integrity Checks

Short Description:
The server wrongly assumes that hidden, non-editable, or client-side-controlled fields are trustworthy and does not re-check them against server-side state and authorization rules.

Relevant BL Abuse Types:
- BLA3 – Object State Manipulations: injecting values into hidden or non-editable fields to move objects into states that should be gated by authorization or validation.
- BLA9 – Broken Access Control: non-privileged users performing actions reserved for admins or other roles by crafting requests with hidden parameters.
- BLA8 – Internal State Disclosure: abuse or manipulation of logs and other state artifacts to infer or corrupt internal state.

Business Rules (Expected Behavior):
- Hidden inputs or non-editable fields in the UI should never be the sole source of truth for authorization or business decisions.
- The server should maintain its own authoritative view of sensitive data (e.g., allowed projects, target usernames, balances) and re-derive or verify these fields on each sensitive operation.
- Only authorized identities should be able to alter specific records or business objects.

Typical Violations / Examples:
- Non-admin user crafts a request containing username and password fields (normally visible only to admin UI) and successfully resets other users' passwords.
- User modifies a dropdown-backed project identifier in the request to access a project they were not assigned in the UI.
- Attacker injects or modifies unverified data in backend systems (e.g., DMV records, citizen data, logs), corrupting the integrity of critical records.

HTTP / Traffic Indicators:
Requests from low-privileged sessions containing parameters that:
- Are only present in admin or elevated flows in the baseline sessions.
- Refer to other users or projects not visible in the regular UI for this user.

Edits to data that:
- Should be read-only at a given business stage but are changed via direct request manipulation.

Test / Detection Heuristics (LLM over HAR):
For a given user/session:
- Compare which identifiers / target objects they can see in the "browse" or "list" views vs which they reference in state-changing requests.

Flag:
- Any update/create/delete action on an object that never appeared in that session's readable set (candidate for IDOR + integrity violation).
- Password changes or role changes triggered by non-admin sessions.

Pattern 4 – Process Timing

WSTG-BUSL-04 – relevant mainly to Missing Transition Validation (BLA6); sometimes to Object State Manipulations (BLA3)

Name: Process Timing & Time-Window Abuse

Short Description:
Business logic depends on timing (timeouts, reservation windows, price validity), but the application fails to enforce time-related constraints consistently, allowing users to hold resources or lock in favorable states beyond the intended window.

Relevant BL Abuse Types:
- BLA6 – Missing Transition Validation: transitions accepted when time-based preconditions (e.g., "quote valid for 5 minutes") are no longer true.
- BLA3 – Object State Manipulations: keeping objects in "reserved" or "pending" states indefinitely to block others or abuse pricing.

Business Rules (Expected Behavior):
- Transactions that exceed a defined time window should be invalidated or re-priced.
- Seat reservations, price quotes, and similar temporary states must either expire automatically or be rolled back if finalization does not happen within a bounded time.

Typical Violations / Examples:
- Ticket purchase: user reserves many seats but never completes checkout, causing denial of availability without proper timeout/release.
- Precious metals e-commerce: user locks a price at time T0 and completes the transaction at time T1 after the market price has changed, still receiving the old price.

HTTP / Traffic Indicators:
Long gaps in time between:
- Initial reservation / quote creation request.
- Final confirmation / payment request.

Completion requests that:
- Reference a reservation or quote ID created far outside the intended time window but are still accepted.

Test / Detection Heuristics (LLM over HAR):
For each reservation/quote ID:
- Compute the time delta between creation and finalization requests in the HAR.

Flag:
- Finalizations that occur after unusually long times without intermediate validation steps.
- Lack of any "revalidation" or "refresh" call before finalization after a long idle period.

Pattern 5 – Number of Times a Function Can Be Used (Limits)

WSTG-BUSL-05 – very close to Object State Manipulations (BLA3) and Missing Transition Validation (BLA6); also used in misuse-detection logic for Defenses Against Application Misuse / Shadow Function Abuse

Name: Limit Abuse of Business Functions

Short Description:
Functions that are supposed to have strict usage limits per user, per transaction, or per period (e.g., discounts, free trials, downloads) can be executed more often than intended.

Relevant BL Abuse Types:
- BLA3 – Object State Manipulations: repeatedly applying a state-changing function that should be single-use (e.g., cumulatively stacking discounts).
- BLA6 – Missing Transition Validation: missing checks that prevent repeated execution of a one-time transition.
- Supports BLA10 – Shadow Function Abuse when combined with hidden discount or benefit functions.

Business Rules (Expected Behavior):
- Certain operations must be restricted in frequency or count (e.g., "one discount per transaction", "3 downloads per month").
- Attempts to reuse these operations beyond allowed limits should be rejected and logged.

Typical Violations / Examples:
- Applying the same promotional discount multiple times by navigating back in the flow or replaying a discount application request.
- Exceeding subscription usage limits (e.g., downloads/view quotas) because the server does not track or enforce usage at the back end.

HTTP / Traffic Indicators:
Multiple requests from the same user/session in a short period that:
- Hit the same discount-application endpoint with the same code.
- Invoke a function that business docs say should be single-use per transaction or per period.

Sequential state-change requests where:
- Application state clearly reflects the effect of prior calls, yet a subsequent call with the same intent is still successfully processed.

Test / Detection Heuristics (LLM over HAR):
For each logical transaction or period:
- Count how many times specific functions (discount application, free trial activation, quota-based operations) are invoked.

Flag:
- Cases where the same function or discount code is successfully used more often than documented or typical for normal behavior.

Pattern 6 – Circumvention of Workflows

WSTG-BUSL-06 – canonical for Missing Transition Validation (BLA6); often interacts with Object State Manipulations (BLA3) and Broken Access Control (BLA9)

Name: Circumvention of Business Workflows

Short Description:
The user completes a business process while skipping or reordering steps that should be mandatory, or by failing to roll back side effects if the overall process is not properly completed.

Relevant BL Abuse Types:
- BLA6 – Missing Transition Validation: state transitions accepted without ensuring all prerequisite steps were completed in the correct order.
- BLA3 – Object State Manipulations: accumulated benefits (e.g., loyalty points) persist despite transaction rollback or cancellation.
- BLA9 – Broken Access Control: using partial transaction states to gain access to content or functionality not normally permitted.

Business Rules (Expected Behavior):
- Workflows must enforce ordered steps; skipping or reordering should invalidate the transaction or trigger rollback.
- Any side effects (points, credits, posts) must be consistent with the final outcome of the transaction. If a transaction is cancelled or fails, side effects should be rolled back.

Typical Violations / Examples:
- Loyalty points are awarded during an early step; user then cancels the transaction or reduces the basket but retains full points.
- Bulletin board / CMS requires profanity checks on initial posts but not on edits; user posts clean content then later updates the content to bypass filters.

HTTP / Traffic Indicators:
Sequences where:
- A side-effecting operation (e.g., awarding points) occurs before final commit/payment and is not reversed when the transaction is cancelled or modified.
- Content or state-changing "edit" operations are executed without re-running the same validation logic applied at creation.

Request order anomalies:
- Direct access to late-stage endpoints (/confirm, /success, /finalize) without the usual preceding chain of initialization and validation calls seen in normal traces.

Test / Detection Heuristics (LLM over HAR):
Compare:
- The typical "happy-path" workflow vs alternate sequences in the HAR that reach equivalent end states with fewer/different steps.

Flag:
- Cases where benefits are credited prior to final commitment and no compensating transaction exists after cancellation / rollback.
- Edit/update requests that result in invalid post-conditions relative to documented rules (e.g., content now contains forbidden elements).

Pattern 7 – Defenses Against Application Misuse

WSTG-BUSL-07 – highly relevant as defensive context for Shadow Function Abuse (BLA10), Broken Access Control (BLA9), State Manipulations (BLA3), Missing Transitions (BLA6), Internal State Disclosure (BLA8)

Name: Lack of Active Defenses Against Application Misuse

Short Description:
The application lacks monitoring and runtime defenses for suspicious sequences of actions, allowing prolonged probing and abuse of business logic without any throttling, lockout, or escalation.

Relevant BL Abuse Types:
- BLA10 – Shadow Function Abuse: repeated probing to discover hidden endpoints/params without detection.
- BLA9 – Broken Access Control: multiple unauthorized access attempts with no reaction from the application.
- BLA3/BLA6/BLA8: persistent experimentation to reverse-engineer internal state transitions and constraints.

Business Rules (Expected Behavior):
- The system should detect and react to patterns of misuse (e.g., repeated access control failures, high-rate function calls, invalid structured inputs).
- Responses may include rate-limiting, account lockout, extra authentication, or logging & alerting.

Typical Violations / Examples:
A user repeatedly:
- Requests unauthorized resources, injects suspicious payloads, or manipulates parameters.
- Interacts with multi-stage business processes in obviously wrong orders.

The application:
- Returns generic responses and allows operations to continue without slowing, blocking, or logging the behavior.

HTTP / Traffic Indicators:
High volume of:
- Access control failures, invalid parameter combinations, malformed JSON/XML, or blatant attack payloads, with no visible change in server behavior.

Absence of:
- Any error escalation, additional auth steps, or throttling in response to misuse patterns.

Test / Detection Heuristics (LLM over HAR):
Scan the HAR for:
- Repeated 4xx/5xx patterns or validation failures followed by continued normal responses.

Flag:
- Situations where a client performs numerous anomalous operations (invalid IDs, wrong order flows, injection-style payloads) without triggering any defensive state change on the server side.

Pattern 8 – Excessive Trust in Client-Side Controls

PortSwigger: "Excessive trust in client-side controls" – Extends Pattern 3

Short Description:
The server assumes that because the UI restricts an action (e.g., a grayed-out button or a hidden field), the user cannot perform it. Attackers bypass the UI to submit values that should be server-derived.

Business Rules (Expected Behavior):
- Transaction-critical values (price, discount rates, user roles, shipping costs) must be derived or validated server-side, regardless of what the client sends.
- Client-side validation is for UX only; it is not a security boundary.

Typical Violations / Examples:
- Changing a product price from $100 to $0.01 in the POST request.
- Modifying a hidden input field that determines the access_level or subscription_plan.

HTTP / Traffic Indicators:
- Requests where the client supplies values that are typically static or calculated (e.g., total_price, is_admin=false).
- Discrepancies between the "Product Page" GET response (price: 100) and the "Add to Cart" POST request (price: 1).

Test / Detection Heuristics (LLM over HAR):
- Heuristic: Identify all parameters in state-changing requests. Cross-reference them with previous GET responses. If a value is "hardcoded" in the request but was never provided by the server as an editable field, flag it for tampering.

Pattern 9 – Unconventional Input Handling (Boundary & Type Abuse)

PortSwigger: "Failing to handle unconventional input" – Extends Pattern 1

Short Description:
The application logic fails when receiving inputs that are syntactically correct (e.g., an integer) but logically nonsensical (e.g., negative quantity, extreme values).

Business Rules (Expected Behavior):
- Numeric inputs must be checked for logical bounds (e.g., quantity > 0).
- Financial logic must ensure that "negative" operations do not invert the intended business direction (e.g., negative transfers).

Typical Violations / Examples:
- Negative Quantity: Ordering -10 items to receive a "refund" or reduce the total cart price.
- Integer Overflow: Submitting a quantity so large it causes a wrap-around in the price calculation logic.

HTTP / Traffic Indicators:
- Parameters like qty, amount, points, or balance containing negative signs or scientific notation (e.g., 1e10).

Test / Detection Heuristics (LLM over HAR):
- Heuristic: For every numeric parameter, simulate "What if this was -1?" or "What if this was 999999?". If the server response (200 OK) suggests the value was accepted into the state, flag as a validation failure.

Pattern 10 – Mandatory Input Omission

PortSwigger: "Users won't always supply mandatory input"

Short Description:
The server assumes certain parameters will always be present. Removing them might bypass specific logic checks or trigger "default" code paths that are less secure.

Business Rules (Expected Behavior):
- The absence of a required parameter should trigger a "400 Bad Request" or a safe failure, not a fallback to an unauthenticated or privileged state.

Typical Violations / Examples:
- Removing a password parameter in a "Update Profile" request to see if the server skips the credential check but still updates the email.
- Deleting a role_id parameter to see if the system defaults the user to a "Super Admin" or "Guest" with unintended permissions.

HTTP / Traffic Indicators:
- Successful (200 OK) responses to requests where key parameters seen in "normal" traces are missing.

Test / Detection Heuristics (LLM over HAR):
- Heuristic: Compare a "normal" request with a "tampered" one where one parameter is deleted. If the server still transitions the object state successfully, flag the omitted parameter as a potential logic bypass.

Pattern 11 – Eligibility Drift (Domain-Specific Thresholds)

PortSwigger: "Domain-specific flaws" – Extends Pattern 6

Short Description:
A user meets a requirement for a benefit (e.g., a discount), then changes the state so they no longer meet the requirement, but the benefit persists because the server doesn't re-validate.

Business Rules (Expected Behavior):
- Eligibility for discounts, free shipping, or access must be re-evaluated at the final "Commit" or "Payment" step.

Typical Violations / Examples:
- Cart Manipulation: Add items to reach a $100 free-shipping threshold → Apply free shipping → Remove items so the total is $10 → Checkout still has free shipping.

HTTP / Traffic Indicators:
- A sequence where a "Discount Applied" event occurs, followed by "Remove Item" events, without a corresponding "Discount Removed" or "Recalculate" event before the final "Purchase" request.

Test / Detection Heuristics (LLM over HAR):
- Heuristic: Track the "Invariants" of a benefit. If the conditions for a benefit (e.g., Total > 100) are violated in the HAR sequence but the benefit remains in the final state-change request, flag as Eligibility Drift.

Pattern 12 – Multi-Step Sequence Bypass (2FA/Workflow)

PortSwigger: "Users won't always follow the intended sequence" – Extends Pattern 6

Short Description:
The application assumes users will hit endpoints in order (A -> B -> C). Attackers jump directly from A to C, skipping mandatory intermediate checks (like 2FA or Terms of Service).

Business Rules (Expected Behavior):
- Each step in a workflow must verify that the immediately preceding step was completed successfully.
- Accessing a "Success" or "Finalize" page should be impossible without a valid session state from the "Validation" step.

Typical Violations / Examples:
- 2FA Bypass: Logging in (Step 1) and then manually navigating to /dashboard (Step 3), skipping the /verify-code (Step 2) page.

HTTP / Traffic Indicators:
- A HAR sequence that reaches a high-privilege endpoint without the intermediate POST requests or specific session cookies/tokens generated by the "check" steps.

Test / Detection Heuristics (LLM over HAR):
- Heuristic: Map the "Dependency Graph" of the workflow. If the LLM sees a "Finalize" request without a preceding "Validate" request in the same session, flag as a Sequence Bypass.

Pattern 13 – Encryption Oracle Abuse

PortSwigger: "Providing an encryption oracle"

Short Description:
The application provides a way for a user to encrypt arbitrary data (e.g., a "Share" feature that encrypts a URL). The attacker uses this to craft valid encrypted strings for other sensitive parameters.

Business Rules (Expected Behavior):
- Encrypted blobs should be tied to a specific context/purpose (e.g., using different keys or "purpose" tags) so they cannot be reused across different functions.

Typical Violations / Examples:
- Using an "Encrypt Search Query" feature to generate a ciphertext that is then submitted to an "Admin Command" endpoint that expects encrypted instructions.

HTTP / Traffic Indicators:
- One endpoint returns an opaque, encrypted-looking string based on user input.
- Another endpoint accepts a similarly formatted string as a sensitive parameter.

Test / Detection Heuristics (LLM over HAR):
- Heuristic: Identify "Symmetric Opaque Blobs." If the LLM sees a string generated in one context (Response A) being used as a parameter in a completely different context (Request B), flag as a potential Oracle Abuse.
