### Business Logic Abuse Knowledge Base (for RAG)

#### BLA3:2025 – Object State Manipulations (OSM)

- **High‑level description**
  Object state manipulation flaws arise when APIs bind user‑supplied data directly into internal objects without filtering allowed fields or validating types. Attackers can override protected properties (e.g., roles, flags, balances) using mass assignment or type‑smuggling techniques.

- **Core business logic rule (what should hold)**
  - Only a restricted set of fields may be controlled by the client; sensitive attributes (roles, permissions, balances, flags, limits) must be server‑controlled.
  - All incoming data must respect strict type validation and conversion rules; the server must reject or normalize values that do not match the expected type/domain.

- **Typical root causes (for reasoning)**
  - Mass assignment:
    - Server automatically maps all JSON fields from the request body into internal objects without whitelisting allowed properties.
    - Framework features (ORM/serializer) write arbitrary payload fields directly into model attributes.
  - Data type smuggling:
    - Loose or implicit type conversions accept values like `"true"` vs `true`, `"1e4"` vs `1`, `"0"` vs `0`.
    - Numeric and boolean checks rely on superficial parsing instead of strict schema validation.

- **BLV indicators in HTTP traffic sequences**
  - Requests where:
    - Extra fields appear in JSON bodies that are not part of the documented client contract, especially:
      - `role`, `is_admin`, `is_superuser`, `permission`, `status`, `balance`, `limit`, `discount`, `quota`, `price`.
    - Numeric or monetary parameters are provided in unusual formats:
      - Scientific notation (`"1e4"`, `"1e9"`), very large integers, or string‑encoded numbers.
    - Boolean flags are supplied as strings (`"true"`, `"false"`, `"1"`, `"0"`) in systems that should expect real booleans.
  - State changes in later responses (e.g., account role, wallet balance, feature enablement) that are not justified by the documented workflow or business rules.

- **Representative attack patterns**
  - Privilege escalation by adding or modifying fields like:
    - `"is_superuser": true`, `"role": "admin"`, `"is_premium": true` in update profile or user management APIs.
  - Wallet or balance abuse via type smuggling:
    - Sending `"amount": "1e4"` to a top‑up or transfer endpoint that expects a small integer amount.
  - Silent modification of protected flags (e.g., `is_verified`, `approved`, `locked`, `limit_override`) in any multi‑field update request.

- **What an automated BLV test should look for (OSM‑oriented)**
  - Suspicious parameters in request bodies that overlap with internal state fields usually controlled by the server.
  - Sequences where a single client request directly triggers high‑impact state transitions (role change, large balance jump) without any intermediate approval, verification, or server‑initiated event.

---

#### BLA6:2025 – Missing Transition Validation (MTV)

- **High‑level description**
  Missing transition validation flaws occur when multi‑step workflows fail to re‑validate prerequisites at each step or fail to enforce them atomically. Attackers call later‑stage endpoints directly, skip validation steps, or race validations, enabling unauthorized transitions through the business process.

- **Core business logic rule (what should hold)**
  - Every step in a multi‑step workflow must independently verify all critical preconditions (authentication, authorization, status flags, publication state, payment state, approvals, MFA completion).
  - Final or sensitive actions must not rely solely on assumptions that earlier steps were completed correctly; they must re‑check server‑side state.

- **Typical root causes (for reasoning)**
  - Workflow split into multiple endpoints without consistent server‑side checks on each endpoint.
  - Final endpoints trust client‑supplied step indicators (e.g., `step`, `status`, `is_verified`, `is_published`) instead of checking persisted state.
  - Middleware or cross‑cutting checks can be bypassed by specific headers, routes, or alternate execution paths.

- **BLV indicators in HTTP traffic sequences**
  - Requests where:
    - A final action endpoint (e.g., checkout, approve, finalize, publish, transfer, delete) is called without prior calls to prerequisite endpoints in the same session.
    - Parameters include step/phase indicators like `step=2`, `completed=true`, `verified=true`, `status="APPROVED"` that the server appears to trust without validating.
    - Entities that have been “unpublished”, “deleted”, or “disabled” are still processed by later endpoints as if they were valid.
  - Inconsistent sequences:
    - Product/order/resource states change to “completed” or “fulfilled” without visible checks for availability, publication, stock, or approval in prior requests.

- **Representative attack patterns**
  - Checkout or purchase of unpublished / deleted items by:
    - Directly sending a `checkout` or `purchase` request for an item ID that was previously unpublished or removed.
  - Middleware/guard bypass:
    - Using specially crafted headers or alternate routes that skip authentication/authorization middleware, leading directly to protected resources or actions.
  - Step skipping in verification flows:
    - Jumping directly to confirmation endpoints (e.g., `/confirm`, `/finalize`) without presenting valid OTP, email token, or second‑factor evidence in this session.

- **What an automated BLV test should look for (MTV‑oriented)**
  - Compare the observed request sequence against the inferred _Application State Map_:
    - Flag cases where a request transitions the business object into a later state without the required prior transitions.
  - Identify endpoints whose behavior (e.g., successful checkout) contradicts the known object state (e.g., item unpublished, account not verified).

---

#### BLA8:2025 – Internal State Disclosure (ISD)

- **High‑level description**
  Internal state disclosure vulnerabilities arise when systems expose differences in internal states through external signals: error messages, UI variations, response codes, response bodies, timing, or other side channels. Attackers use these signals to enumerate resources, map workflows, and infer hidden business conditions.

- **Core business logic rule (what should hold)**
  - External responses should not reveal whether a given username, account, resource ID, or internal status is valid, existing, privileged, or specific to a business process step.
  - Systems should normalize error handling, messages, and timing so that invalid and valid cases look indistinguishable from an attacker’s point of view.

- **Typical root causes (for reasoning)**
  - Distinct error messages for different failure reasons (e.g., “Username not found” vs “Incorrect password”).
  - Detailed validation or debugging messages exposed in production (stack traces, SQL errors, field‑level reasons).
  - Conditional UI elements or API responses that only appear for valid accounts/resources.
  - Measurable timing differences between valid and invalid cases (e.g., password hashing only for existing users).

- **BLV indicators in HTTP traffic sequences**
  - Pairs of similar requests where only a single input (e.g., username, account ID, email, resource ID) is changed, and:
    - Response messages differ in wording, structure, or error code.
    - Response bodies include additional fields or detail for valid identifiers.
    - Response time consistently differs (e.g., significantly slower for existing accounts).
  - Authentication, registration, password reset, or lookup endpoints that:
    - Explicitly confirm account existence or status in response texts or codes.

- **Representative attack patterns**
  - Account enumeration via:
    - Login attempts that distinguish “non‑existent user” vs “wrong password”.
    - Password reset flows that say “email not registered” vs “reset link sent”.
  - Resource existence probing:
    - Different HTTP status or body content for `/resource/123` vs `/resource/999999`, revealing which IDs are valid.
  - Timing side‑channels:
    - Measuring latency differences between requests with valid vs invalid identifiers to compile a list of real accounts or high‑value targets.

- **What an automated BLV test should look for (ISD‑oriented)**
  - Cluster similar requests and compare:
    - Status codes, error messages, JSON fields, and latency, given minimal changes in input.
  - Flag endpoints where the only changed parameter is an identifier, but the response reveals clear semantic differences (existence, role, state, or workflow position).

---

#### BLA9:2025 – Broken Access Control (BAC)

- **High‑level description**
  Broken access control in a business logic context occurs when role‑ or permission‑gated workflows are exposed without proper server‑side checks, or when authorization relies on client‑controlled data. Attackers can perform sensitive operations, escalate privileges, or manipulate other users’ resources by tampering with identifiers and role indicators.

- **Core business logic rule (what should hold)**
  - Every sensitive operation (creation, update, deletion, approval, configuration) must verify that:
    - The caller is authenticated, and
    - The caller’s role/permissions allow this action on this specific object or scope.
  - Authorization decisions must be derived from server‑side state, not from client‑supplied role or identity claims.

- **Typical root causes (for reasoning)**
  - Endpoints that:
    - Omit role/permission checks entirely.
    - Accept any authenticated token for high‑risk actions.
  - Business logic that:
    - Trusts client‑supplied headers or parameters (e.g., `X-User-Role`, `isAdmin`, `userId`) to make access decisions.
  - Overly broad or misconfigured access control lists (ACLs) and default permissions.
  - Insecure direct object references / BOLA:
    - Access decisions use object IDs in URLs or bodies without verifying ownership or access rights.

- **BLV indicators in HTTP traffic sequences**
  - Requests from low‑privilege sessions (or mixed user identities) that:
    - Successfully perform actions expected only for admins, managers, or resource owners (e.g., delete project branches, change permissions, approve payments).
  - Requests where:
    - The only significant change is an ID or role‑related field, yet the system still returns success on objects that should be out of scope.
    - Caller can update their own permissions or roles using generic update endpoints.
  - Repeated patterns of:
    - Editing or deleting resources belonging to other users by incrementing or guessing IDs in the path or body.

- **Representative attack patterns**
  - Role bypass:
    - Non‑admin users successfully call endpoints like branch deletion, account management, configuration changes, or admin operations without being checked server‑side.
  - Self‑privilege escalation:
    - Users updating their own permission objects (e.g., household/group/tenant permissions) to gain admin‑level capabilities.
  - Cross‑tenant / cross‑user access:
    - Changing path parameters or JSON `userId`, `accountId`, `tenantId`, `orderId` to operate on other entities and getting 200 OK with real data or state changes.

- **What an automated BLV test should look for (BAC‑oriented)**
  - Compare actions across sessions with different inferred privilege levels:
    - Flag when low‑privilege sessions successfully invoke high‑risk endpoints or modify foreign resources.
  - Detect patterns where resource IDs are the only differentiator, yet access results are uniformly successful, suggesting missing ownership checks.

---

#### BLA10:2025 – Shadow Function Abuse (SFA)

- **High‑level description**
  Shadow Function Abuse involves hidden, undocumented, deprecated, or internally intended endpoints and features that remain reachable in production without proper access control. Attackers discover these “shadow functions” and leverage them to bypass normal workflows, authentication, or authorization, gaining unauthorized capabilities.

- **Core business logic rule (what should hold)**
  - Only documented, governed, and access‑controlled endpoints should be reachable in production environments.
  - Internal or deprecated functions must be disabled, protected, or isolated; there should be no alternate paths that bypass normal authentication/authorization layers.

- **Typical root causes (for reasoning)**
  - Shadow functionality:
    - Features created by teams or tools outside formal governance, never subjected to security review.
  - Deprecated functionality:
    - Old admin or test endpoints left active after migration, upgrade, or refactor.
  - Obscured capabilities:
    - Alternate routes, parameters, or protocols (e.g., alternate WebSocket endpoints) that bypass token checks or middleware.

- **BLV indicators in HTTP traffic sequences**
  - Endpoints that:
    - Are rarely used by normal user flows but appear in traffic with high privilege effect (admin actions, direct access to configuration, data export, management features).
    - Sit outside the main documented URL structure (e.g., `/internal/`, `/debug/`, `/old_admin/`, alternate paths like `/ws/` vs `/api/ws/`).
  - Requests where:
    - No authentication or role check is visible in the normal workflow, yet powerful actions succeed.
    - Query parameters like `adminstep`, `debug`, `test`, `bypass`, or similar are present and drastically alter behavior.
  - Mismatches between:
    - The expected path for a feature (e.g., `/admin`, `/api/admin`) and the actual path used in the attack sequence (e.g., `/lp_admin.php?adminstep=`, `/ws/` for CLI commands).

- **Representative attack patterns**
  - Hidden admin parameter:
    - Direct access to an admin panel or privileged view by requesting a legacy script with a special parameter, without any credential check.
  - Alternate protocol path:
    - Using a non‑documented WebSocket endpoint that bypasses authentication and grants full administrative command execution.

- **What an automated BLV test should look for (SFA‑oriented)**
  - Identify “outlier” endpoints in the traffic:
    - Low frequency, high impact, structurally different paths compared to the main API.
  - Flag sequences where:
    - Sensitive operations are performed via routes that do not appear in the normal business flow derived from HAR.
    - Privileged behavior is observed without preceding authentication/authorization seen elsewhere in the application.
