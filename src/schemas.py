from pydantic import BaseModel, Field, Extra
from typing import List, Optional, Literal, Dict, Any, Union
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

class Signal(str, Enum):
    REFLECTED_INPUT = "reflected_input"
    RESPONSE_LENGTH_DIFF = "response_length_diff"
    STATUS_CODE_CHANGE = "status_code_change"
    ERROR_SIGNATURE = "error_signature"
    TIMING_ANOMALY = "timing_anomaly"
    HEADER_CHANGE = "header_change"
    XSS_PAYLOAD_EXECUTED = "xss_payload_executed"
    SQL_ERROR_LEAKED = "sql_error_leaked"
    DIRECTORY_LISTING = "directory_listing"
    SENSITIVE_DATA_EXPOSED = "sensitive_data_exposed"
    AUTHENTICATION_BYPASSED = "authentication_bypassed"
    AUTHORIZATION_BYPASSED = "authorization_bypassed"
    DNS_CALLBACK = "dns_callback"
    HTTP_CALLBACK = "http_callback"
    SMTP_CALLBACK = "smtp_callback"

class PassLogic(str, Enum):
    ANY = "any"
    ALL = "all"

class PayloadTier(str, Enum):
    BENIGN = "benign"
    PROBE = "probe"
    EXPLOIT = "exploit"
    DESTRUCTIVE = "destructive"

class PrerequisiteType(str, Enum):
    LOGIN = "login"
    CSRF_TOKEN = "csrf_token"
    JWT_REFRESH = "jwt_refresh"
    SESSION_STATE = "session_state"
    CUSTOM = "custom"

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

class SafetyConfig(BaseModel, extra=Extra.forbid):
    idempotent_required: bool = Field(default=True)
    destructive_ok: bool = Field(default=False)
    max_requests: int = Field(default=10, ge=1)

class Threshold(BaseModel, extra=Extra.forbid):
    timing_ms: Optional[int] = None
    body_length_delta_pct: Optional[float] = None
    expected_codes: Optional[List[int]] = None

class Oracle(BaseModel, extra=Extra.forbid):
    signal: Signal
    threshold: Optional[Threshold] = None
    description: Optional[str] = None

class KeyValue(BaseModel, extra=Extra.forbid):
    key: str
    value: str

class VulnHypothesis(BaseModel, extra=Extra.forbid):
    id: str
    method: str
    endpoint: str
    parameter: str
    param_location: str
    category: str

    oracles: List[Oracle]
    pass_logic: PassLogic = PassLogic.ANY

    preconditions: Optional[List[KeyValue]] = None
    safety: SafetyConfig = Field(default_factory=SafetyConfig)

    confidence: float = Field(ge=0.0, le=1.0)
    priority: int = Field(ge=1, le=5)

class VulnHypothesesContext(BaseModel, extra=Extra.forbid):
    hypotheses: List[VulnHypothesis]
    metadata: Optional[List[KeyValue]] = None

class OracleThreshold(BaseModel, extra=Extra.forbid):
    timing_ms: Optional[int] = None
    body_length_delta_pct: Optional[float] = None
    expected_codes: Optional[List[int]] = None
    numeric_value: Optional[float] = None
    string_value: Optional[str] = None

class OracleRule(BaseModel, extra=Extra.forbid):
    signal: Signal
    condition: str
    threshold: Optional[OracleThreshold] = None
    weight: float = Field(default=1.0, ge=0.0, le=1.0)

class Prerequisite(BaseModel, extra=Extra.forbid):
    type: PrerequisiteType
    description: str
    extract_from: Optional[str] = None
    bind_to: Optional[str] = None
    custom_logic: Optional[str] = None

class PayloadValues(BaseModel, extra=Extra.forbid):
    location: str
    value: str

class TestPayload(BaseModel, extra=Extra.forbid):
    tier: PayloadTier
    payloads: List[PayloadValues]
    description: str
    encoding: Optional[str] = None
    content_type: Optional[str] = None

class TestCase(BaseModel, extra=Extra.forbid):
    id: str
    hypothesis_id: str

    # HTTP Request details
    base_url: str
    method: str
    endpoint: str
    parameter: str

    # Test configuration
    payloads: List[TestPayload]
    prerequisites: List[Prerequisite] = Field(default_factory=list)

    # Detection rules
    oracle_rules: List[OracleRule]
    pass_logic: PassLogic = PassLogic.ANY

    # Safety and execution
    safety: SafetyConfig
    max_retries: int = Field(default=3, ge=1)
    delay_between_requests: float = Field(default=1.0, ge=0.0)

    # Metadata
    notes: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    estimated_duration: Optional[int] = None

class TestCasesContext(BaseModel, extra=Extra.forbid):
    test_cases: List[TestCase]
    global_prerequisites: List[Prerequisite] = Field(default_factory=list)
    execution_hints: Optional[List[KeyValue]] = None
    metadata: Optional[List[KeyValue]] = None