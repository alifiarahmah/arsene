from pydantic import BaseModel, Field
from typing import List, Optional, Literal, Dict, Any
from enum import Enum

class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"

class AuthScheme(str, Enum):
    COOKIE = "cookie"
    JWT = "jwt"
    OAUTH2 = "oauth2"
    API_KEY_HEADER = "api_key_header"
    API_KEY_QUERY = "api_key_query"
    BASIC_AUTH = "basic_auth"
    NONE = "none"

class CSRFProtection(str, Enum):
    TOKEN_IN_FORM = "token_in_form"
    DOUBLE_SUBMIT_COOKIE = "double_submit_cookie"
    SAME_SITE_COOKIE = "same_site_cookie"
    NONE = "none"

class SideEffect(str, Enum):
    READ_ONLY = "read_only"
    STATE_CHANGING = "state_changing"
    UNKNOWN = "unknown"

class AntiAutomation(str, Enum):
    CAPTCHA = "captcha"
    RATE_LIMIT = "rate_limit"
    USER_AGENT_CHECKS = "user_agent_checks"
    IP_BLOCKING = "ip_blocking"
    CSRF = "csrf"
    NONE = "none"

class ParamLocation(str, Enum):
    QUERY = "query"
    PATH = "path"
    HEADER = "header"
    COOKIE = "cookie"
    BODY = "body"

class SessionManagement(str, Enum):
    COOKIE = "cookie"
    JWT = "jwt"
    URL_REWRITE = "url_rewrite"

class AuthFlow(str, Enum):
    FORM_LOGIN = "form_login"
    OAUTH2 = "oauth2"
    SAML = "saml"
    NONE = "none"

class Parameter(BaseModel):
    name: str
    location: ParamLocation
    sample_value: Optional[str] = None

class Endpoint(BaseModel):
    method: HttpMethod
    path_template: str
    auth_schemes: List[AuthScheme] = []
    roles: List[str] = []
    csrf_protection: Optional[CSRFProtection] = None
    side_effect: Optional[SideEffect] = None
    anti_automation: List[AntiAutomation] = []
    protocol: Optional[Literal["http", "https"]] = None
    content_types: List[str] = []
    parameters: List[Parameter] = []
    tokens_observed: List[str] = []
    needs_observation: bool = False

class GlobalObservations(BaseModel):
    session_management: Optional[SessionManagement] = None
    token_lifetime_estimate: Optional[int] = None
    auth_flow: Optional[AuthFlow] = None
    needs_observation: bool = False

class TrafficAnalysisContext(BaseModel):
    endpoints: List[Endpoint]
    global_observations: GlobalObservations

class AttackCategory(str, Enum):
    INJECTION_SQL = "injection_sql"
    INJECTION_NOSQL = "injection_nosql"
    INJECTION_XPATH = "injection_xpath"
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    SSRF = "ssrf"
    COMMAND_INJECTION = "command_injection"
    FILE_INCLUSION = "file_inclusion"
    DESERIALIZATION = "deserialization"
    INSECURE_DIRECT_OBJECT_REFERENCE = "insecure_direct_object_reference"
    AUTHZ_BYPASS = "authz_bypass"
    AUTHN_BYPASS = "authn_bypass"
    CSRF = "csrf"
    OPEN_REDIRECT = "open_redirect"
    XXE = "xxe"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    BUSINESS_LOGIC = "business_logic"
    OTHERS = "others"

class ExpectedSignal(str, Enum):
    STATUS_CODE_CHANGE = "status_code_change"
    RESPONSE_LENGTH_DIFF = "response_length_diff"
    ERROR_SIGNATURE = "error_signature"
    REFLECTED_INPUT = "reflected_input"
    TIMING_VARIATION = "timing_variation"
    OUT_OF_BAND_CALL = "out_of_band_call"
    HEADER_INJECTION = "header_injection"
    TOKEN_REUSE_FAILURE = "token_reuse_failure"
    STATE_CHANGE_OBSERVED = "state_change_observed"
    NONE = "none"

class AttackVector(BaseModel):
    method: Optional[str] = None
    endpoint: str
    parameter: Optional[str] = None
    param_location: Optional[ParamLocation] = None
    sample_value: Optional[str] = None
    category: AttackCategory
    expected_signals: List[ExpectedSignal]
    needs_observation: bool

class AttackVectorsContext(BaseModel):
    vectors: List[AttackVector]

class Signal(str, Enum):
    # Response analysis
    REFLECTED_INPUT = "reflected_input"
    RESPONSE_LENGTH_DIFF = "response_length_diff"
    STATUS_CODE_CHANGE = "status_code_change"
    ERROR_SIGNATURE = "error_signature"
    TIMING_ANOMALY = "timing_anomaly"
    HEADER_CHANGE = "header_change"

    # Security-specific
    XSS_PAYLOAD_EXECUTED = "xss_payload_executed"
    SQL_ERROR_LEAKED = "sql_error_leaked"
    DIRECTORY_LISTING = "directory_listing"
    SENSITIVE_DATA_EXPOSED = "sensitive_data_exposed"
    AUTHENTICATION_BYPASSED = "authentication_bypassed"
    AUTHORIZATION_BYPASSED = "authorization_bypassed"

    # Out-of-band
    DNS_CALLBACK = "dns_callback"
    HTTP_CALLBACK = "http_callback"
    SMTP_CALLBACK = "smtp_callback"

class PassLogic(str, Enum):
    ANY = "any"  # At least one signal triggers
    ALL = "all"  # All signals must trigger

class SafetyConfig(BaseModel):
    idempotent_required: bool = Field(default=True, description="Requires read-only operations")
    destructive_ok: bool = Field(default=False, description="Allows potentially destructive operations")
    max_requests: int = Field(default=10, description="Maximum requests for this hypothesis")

class Oracle(BaseModel):
    signal: Signal
    threshold: Optional[Dict[str, Any]] = Field(default=None, description="Numeric thresholds (e.g., {'timing_ms': 5000, 'body_length_delta_pct': 30})")
    description: Optional[str] = Field(default=None, description="Human-readable oracle description")

class VulnHypothesis(BaseModel):
    id: str = Field(description="Unique identifier for this hypothesis")
    method: str = Field(description="HTTP method")
    endpoint: str = Field(description="Target endpoint")
    parameter: str = Field(description="Target parameter name")
    param_location: str = Field(description="Parameter location: body, query, header, path")
    category: str = Field(description="Vulnerability category (e.g., xss_stored, sqli, idor)")

    oracles: List[Oracle] = Field(description="List of detection oracles")
    pass_logic: PassLogic = Field(default=PassLogic.ANY, description="Logic for combining oracle results")

    preconditions: Optional[Dict[str, Any]] = Field(default=None, description="Required context (auth_context, csrf_token, etc.)")
    safety: SafetyConfig = Field(default_factory=SafetyConfig)

    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in this hypothesis (0.0-1.0)")
    priority: int = Field(ge=1, le=5, description="Testing priority (1=highest, 5=lowest)")

class VulnHypotheses(BaseModel):
    hypotheses: List[VulnHypothesis]
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Additional metadata")