from pydantic import BaseModel, Field
from typing import Annotated, Optional, List, Literal
from enum import Enum

# ===== Type Aliases =====
Confidence = Annotated[float, Field(ge=0.0, le=1.0)]
RiskScore = Annotated[int, Field(ge=0, le=10)]
Priority = Annotated[int, Field(ge=1, le=5)]

# ===== STEP S1: Static Init Schemas =====

class StaticFileIndexItem(BaseModel):
    url: str
    file_name: str
    content_type: str
    size_bytes: int
    truncated: bool

class StaticInitOutput(BaseModel):
    file_index: List[StaticFileIndexItem] = Field(default_factory=list)
    needs_observation: bool
    truncated_sources: List[str] = Field(default_factory=list)

# ===== STEP S2: Static Extraction Schemas =====

class HTTPMethodEnum(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"

class CandidateEndpoint(BaseModel):
    source_url: str
    method: Optional[HTTPMethodEnum] = None
    path: str
    base_url: Optional[str] = None
    confidence: Confidence
    evidence_snippet: str

class ClientRoute(BaseModel):
    source_url: str
    route_path: str
    dynamic_params: List[str] = Field(default_factory=list)
    guard_hint: Optional[str] = None
    confidence: Confidence
    evidence_snippet: str

class StorageAccessEnum(str, Enum):
    localStorage = "localStorage"
    sessionStorage = "sessionStorage"
    cookie = "cookie"

class CSRFHintEnum(str, Enum):
    meta_csrf = "meta_csrf"
    double_submit = "double_submit"
    none = "none"

class AuthHint(BaseModel):
    source_url: str
    storage_access: List[StorageAccessEnum] = Field(default_factory=list)
    token_keys: List[str] = Field(default_factory=list)
    auth_header_keys: List[str] = Field(default_factory=list)
    csrf_hints: List[CSRFHintEnum] = Field(default_factory=list)
    evidence_snippet: str

class SensitiveString(BaseModel):
    source_url: str
    value: str
    pattern: str
    confidence: Confidence

class XSSSinkEnum(str, Enum):
    innerHTML = "innerHTML"
    document_write = "document.write"
    eval = "eval"
    setTimeout = "setTimeout"
    location_assign = "location.assign"
    dangerouslySetInnerHTML = "dangerouslySetInnerHTML"

class DataOriginHintEnum(str, Enum):
    url_param = "url_param"
    storage = "storage"
    cookie = "cookie"
    unknown = "unknown"

class XSSSink(BaseModel):
    source_url: str
    sink: XSSSinkEnum
    data_origin_hint: DataOriginHintEnum
    evidence_snippet: str
    confidence: Confidence

class InterestingPatternEnum(str, Enum):
    fetch = "fetch"
    axios = "axios"
    graphql = "graphql"
    websocket = "websocket"
    sse = "sse"
    url_builder = "url_builder"
    template_literal = "template_literal"

class InterestingPattern(BaseModel):
    source_url: str
    pattern: InterestingPatternEnum
    evidence_snippet: str

class StaticExtractionOutput(BaseModel):
    candidate_endpoints: List[CandidateEndpoint] = Field(default_factory=list)
    client_routes: List[ClientRoute] = Field(default_factory=list)
    auth_hints: List[AuthHint] = Field(default_factory=list)
    sensitive_strings: List[SensitiveString] = Field(default_factory=list)
    xss_sinks: List[XSSSink] = Field(default_factory=list)
    interesting_patterns: List[InterestingPattern] = Field(default_factory=list)
    needs_observation: bool

# ===== STEP S3: Static Mapping Schemas =====

class SourcesFlag(BaseModel):
    traffic: bool
    static: bool

class EnrichedEndpoint(BaseModel):
    method: Optional[str] = None
    path_template: str
    sources: SourcesFlag
    static_confidence: Confidence
    auth_hints: dict = Field(default_factory=dict)
    route_paths: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    notes: Optional[str] = None

class HiddenCandidate(BaseModel):
    method: Optional[str] = None
    path: str
    source_url: str
    confidence: Confidence

class EvidenceEnum(str, Enum):
    co_location = "co-location"
    shared_module = "shared_module"
    string_proximity = "string_proximity"
    same_component = "same_component"

class RouteToEndpointLink(BaseModel):
    route_path: str
    endpoint_path: str
    evidence: EvidenceEnum
    confidence: Confidence

class StaticMappingOutput(BaseModel):
    enriched_endpoints: List[EnrichedEndpoint] = Field(default_factory=list)
    hidden_candidates: List[HiddenCandidate] = Field(default_factory=list)
    route_to_endpoint_links: List[RouteToEndpointLink] = Field(default_factory=list)
    needs_observation: bool

# ===== STEP I1: Unified Inventory Schemas =====

class TokenTypeEnum(str, Enum):
    cookie = "cookie"
    jwt = "jwt"
    oauth2 = "oauth2"
    api_key_header = "api_key_header"
    api_key_query = "api_key_query"
    none = "none"

class CategoryEnum(str, Enum):
    auth = "auth"
    file_upload = "file_upload"
    graphql = "graphql"
    admin = "admin"
    search = "search"
    websocket = "websocket"
    sse = "sse"
    generic = "generic"

class ParameterModel(BaseModel):
    name: str
    location: str
    sample_value: Optional[str] = None

class UnifiedEndpoint(BaseModel):
    method: Optional[str] = None
    path_template: str
    sources: SourcesFlag
    static_confidence: Confidence
    auth_required: Optional[bool] = None
    token_types: List[TokenTypeEnum] = Field(default_factory=list)
    parameter_models: List[ParameterModel] = Field(default_factory=list)
    categories: List[CategoryEnum] = Field(default_factory=list)
    risk_score: RiskScore
    notes: Optional[str] = None

class UnifiedInventoryOutput(BaseModel):
    endpoints: List[UnifiedEndpoint] = Field(default_factory=list)
    needs_observation: bool

# ===== STEP I2: Sink Attachment Schemas =====

class SinkDetail(BaseModel):
    sink: str
    data_origin_hint: str
    evidence_snippet: str
    confidence: Confidence

class EndpointSink(BaseModel):
    path_template: str
    method: Optional[str] = None
    sinks: List[SinkDetail] = Field(default_factory=list)

class SinkAttachmentOutput(BaseModel):
    endpoint_sinks: List[EndpointSink] = Field(default_factory=list)
    needs_observation: bool

# ===== STEP 2: Traffic Context Schemas =====

class AuthSchemeEnum(str, Enum):
    cookie = "cookie"
    jwt = "jwt"
    oauth2 = "oauth2"
    api_key_header = "api_key_header"
    api_key_query = "api_key_query"
    basic_auth = "basic_auth"
    none = "none"

class CSRFProtectionEnum(str, Enum):
    token_in_form = "token_in_form"
    double_submit_cookie = "double_submit_cookie"
    same_site_cookie = "same_site_cookie"
    none = "none"

class SideEffectEnum(str, Enum):
    read_only = "read_only"
    state_changing = "state_changing"
    unknown = "unknown"

class AntiAutomationEnum(str, Enum):
    captcha = "captcha"
    rate_limit = "rate_limit"
    user_agent_checks = "user_agent_checks"
    ip_blocking = "ip_blocking"
    csrf = "csrf"
    none = "none"

class ProtocolEnum(str, Enum):
    http = "http"
    https = "https"

class ParamLocationEnum(str, Enum):
    query = "query"
    path = "path"
    header = "header"
    cookie = "cookie"
    body = "body"

class Parameter(BaseModel):
    name: str
    location: ParamLocationEnum
    sample_value: Optional[str] = None

class TrafficEndpoint(BaseModel):
    method: HTTPMethodEnum
    path_template: str
    auth_schemes: List[AuthSchemeEnum] = Field(default_factory=list)
    roles: List[str] = Field(default_factory=list)
    csrf_protection: CSRFProtectionEnum = CSRFProtectionEnum.none
    side_effect: SideEffectEnum = SideEffectEnum.unknown
    anti_automation: List[AntiAutomationEnum] = Field(default_factory=list)
    protocol: ProtocolEnum
    content_types_accepted: List[str] = Field(default_factory=list)
    content_types_response: List[str] = Field(default_factory=list)
    parameters: List[Parameter] = Field(default_factory=list)
    tokens_observed: List[str] = Field(default_factory=list)
    needs_observation: bool = False

class SessionManagementEnum(str, Enum):
    cookie = "cookie"
    jwt = "jwt"
    url_rewrite = "url_rewrite"
    none = "none"

class AuthFlowEnum(str, Enum):
    form_login = "form_login"
    oauth2 = "oauth2"
    saml = "saml"
    none = "none"

class GlobalObservations(BaseModel):
    session_management: SessionManagementEnum
    estimated_token_lifetime_seconds: Optional[int] = None
    authentication_flow: AuthFlowEnum
    needs_observation: bool = False

class TrafficContextOutput(BaseModel):
    endpoints: List[TrafficEndpoint] = Field(default_factory=list)
    global_observations: GlobalObservations
    needs_observation: bool = False

# ===== STEP 3: Attack Vectors Schemas =====

class AttackCategoryEnum(str, Enum):
    sqli = "sqli"
    xss = "xss"
    idor = "idor"
    authz_bypass = "authz_bypass"
    path_traversal = "path_traversal"
    ssrf = "ssrf"
    open_redirect = "open_redirect"
    xxe = "xxe"
    command_injection = "command_injection"
    nosql_injection = "nosql_injection"
    ldap_injection = "ldap_injection"
    ssti = "ssti"
    csrf = "csrf"
    cors_misconfiguration = "cors_misconfiguration"
    jwt_manipulation = "jwt_manipulation"
    race_condition = "race_condition"
    business_logic = "business_logic"

class ExpectedSignalEnum(str, Enum):
    status_code_change = "status_code_change"
    response_length_diff = "response_length_diff"
    timing_anomaly = "timing_anomaly"
    reflected_input = "reflected_input"
    error_message = "error_message"
    oob_interaction = "oob_interaction"
    privilege_escalation = "privilege_escalation"
    data_leakage = "data_leakage"

class AttackVector(BaseModel):
    method: HTTPMethodEnum
    endpoint: str
    parameters: List[str]  # Can be single or multiple params
    param_locations: List[ParamLocationEnum]
    sample_values: List[Optional[str]]
    category: AttackCategoryEnum
    expected_signals: List[ExpectedSignalEnum]
    needs_observation: bool = False

class AttackVectorsOutput(BaseModel):
    vectors: List[AttackVector] = Field(default_factory=list)
    needs_observation: bool = False

# ===== STEP 4: Vulnerability Hypotheses Schemas =====

class PassLogicEnum(str, Enum):
    any = "any"
    all = "all"

class Oracle(BaseModel):
    signal: ExpectedSignalEnum
    threshold: dict = Field(default_factory=dict)  # e.g., {"timing_ms": 5000}
    pass_logic: PassLogicEnum = PassLogicEnum.any

class Precondition(BaseModel):
    auth_context: Optional[dict] = None
    csrf_token_required: bool = False
    session_required: bool = False
    cookies_required: List[str] = Field(default_factory=list)
    headers_required: dict = Field(default_factory=dict)

class SafetyConstraints(BaseModel):
    idempotent_required: bool = False
    max_requests: int = 10
    rate_limit_hint: Optional[str] = None

class VulnerabilityHypothesis(BaseModel):
    method: HTTPMethodEnum
    endpoint: str
    parameters: List[str]
    category: AttackCategoryEnum
    oracles: List[Oracle]
    preconditions: Precondition = Field(default_factory=Precondition)
    safety: SafetyConstraints = Field(default_factory=SafetyConstraints)
    confidence: Confidence
    priority: Priority
    notes: Optional[str] = None

class VulnerabilityHypothesesOutput(BaseModel):
    hypotheses: List[VulnerabilityHypothesis] = Field(default_factory=list)
    needs_observation: bool = False

# ===== STEP 5: Test Case Generation Schemas =====

class PayloadTierEnum(str, Enum):
    benign = "benign"
    probe = "probe"
    exploit = "exploit"

class PayloadValue(BaseModel):
    parameter: str
    location: ParamLocationEnum
    value: str
    tier: PayloadTierEnum

class OracleRule(BaseModel):
    condition: str  # Executable condition string
    signal: ExpectedSignalEnum
    threshold: dict = Field(default_factory=dict)

class Prerequisite(BaseModel):
    headers: dict = Field(default_factory=dict)
    cookies: dict = Field(default_factory=dict)
    auth_token: Optional[str] = None
    csrf_token: Optional[str] = None
    session_id: Optional[str] = None

class TestCase(BaseModel):
    test_id: str
    method: HTTPMethodEnum
    endpoint: str
    category: AttackCategoryEnum
    payloads: List[PayloadValue]  # Includes benign baseline first
    oracle_rules: List[OracleRule]
    prerequisites: Prerequisite = Field(default_factory=Prerequisite)
    safety: SafetyConstraints = Field(default_factory=SafetyConstraints)
    confidence: Confidence
    priority: Priority
    notes: Optional[str] = None

class TestCasesOutput(BaseModel):
    test_cases: List[TestCase] = Field(default_factory=list)
    needs_observation: bool = False

# ===== STEP 6: Chaining & Execution Plan Schemas =====

class ExecutionPhaseEnum(str, Enum):
    authentication = "authentication"
    enumeration = "enumeration"
    probing = "probing"
    exploitation = "exploitation"

class StopConditionEnum(str, Enum):
    first_success = "first_success"
    all_tests = "all_tests"
    max_time = "max_time"
    max_requests = "max_requests"

class ExecutionControl(BaseModel):
    rate_limit_delay_ms: int = 1000
    stop_conditions: List[StopConditionEnum] = Field(default_factory=list)
    max_total_requests: Optional[int] = None
    max_execution_time_seconds: Optional[int] = None

class ChainedTest(BaseModel):
    test_id: str
    phase: ExecutionPhaseEnum
    depends_on: List[str] = Field(default_factory=list)  # test_ids that must run first
    priority_score: Annotated[float, Field(ge=0.0, le=10.0)]
    test_case: TestCase

class ExecutionPlan(BaseModel):
    chained_tests: List[ChainedTest] = Field(default_factory=list)
    execution_control: ExecutionControl = Field(default_factory=ExecutionControl)
    notes: Optional[str] = None

class ExecutionPlanOutput(BaseModel):
    plan: ExecutionPlan
    needs_observation: bool = False