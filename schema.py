from pydantic import BaseModel, Field
from typing import List, Optional
from pydantic import ConfigDict


"""
# TODO: put this?
Output your analysis in JSON format:
{
  "flow_description": "...",
  "missing_validations": [...],
  "manipulable_objects": [...],
  "vulnerabilities": [{"type": "BLA6", "evidence": "Entry #5", "description": "..."}]
}
"""

# Base config for all models to enforce strict schema compliance with OpenAI
STRICT_CONFIG = ConfigDict(extra='forbid')


class HARHeader(BaseModel):
    """HAR header entry."""
    model_config = STRICT_CONFIG

    name: str = Field(description="Header name")
    value: str = Field(description="Header value")


class HARCookie(BaseModel):
    """HAR cookie entry."""
    model_config = STRICT_CONFIG

    name: str = Field(description="Cookie name")
    value: str = Field(description="Cookie value")
    path: Optional[str] = Field(default=None, description="Cookie path")
    domain: Optional[str] = Field(default=None, description="Cookie domain")
    expires: Optional[str] = Field(default=None, description="Cookie expiration date")
    httpOnly: Optional[bool] = Field(default=None, description="HTTP only flag")
    secure: Optional[bool] = Field(default=None, description="Secure flag")
    sameSite: Optional[str] = Field(default=None, description="SameSite attribute")


class HARQueryParam(BaseModel):
    """HAR query parameter."""
    model_config = STRICT_CONFIG

    name: str = Field(description="Query parameter name")
    value: str = Field(description="Query parameter value")


class HARPostParam(BaseModel):
    """HAR post parameter."""
    model_config = STRICT_CONFIG

    name: str = Field(description="Post parameter name")
    value: Optional[str] = Field(default=None, description="Post parameter value")
    fileName: Optional[str] = Field(default=None, description="File name for file uploads")
    contentType: Optional[str] = Field(default=None, description="Content type")


class HARPostData(BaseModel):
    """HAR post data."""
    model_config = STRICT_CONFIG

    mimeType: str = Field(description="MIME type of posted data")
    params: List[HARPostParam] = Field(default_factory=list, description="Post parameters")
    text: Optional[str] = Field(default=None, description="Raw post data text")


class HARRequest(BaseModel):
    """HAR request."""
    model_config = STRICT_CONFIG

    method: str = Field(description="HTTP method (GET, POST, etc.)")
    url: str = Field(description="Full request URL")
    httpVersion: str = Field(description="HTTP version")
    headers: List[HARHeader] = Field(default_factory=list, description="Request headers")
    queryString: List[HARQueryParam] = Field(default_factory=list, description="Query string parameters")
    cookies: List[HARCookie] = Field(default_factory=list, description="Cookies")
    postData: Optional[HARPostData] = Field(default=None, description="Post data")


class HARContent(BaseModel):
    """HAR response content information."""
    model_config = STRICT_CONFIG

    size: Optional[int] = Field(default=None, description="Content size in bytes")
    compression: Optional[int] = Field(default=None, description="Compression saved bytes")
    mimeType: Optional[str] = Field(default=None, description="MIME type")
    text: Optional[str] = Field(default=None, description="Response body text")
    encoding: Optional[str] = Field(default=None, description="Encoding used")


class HARResponse(BaseModel):
    """HAR response."""
    model_config = STRICT_CONFIG

    status: int = Field(description="HTTP status code")
    statusText: str = Field(description="HTTP status text")
    httpVersion: str = Field(description="HTTP version")
    headers: List[HARHeader] = Field(default_factory=list, description="Response headers")
    cookies: List[HARCookie] = Field(default_factory=list, description="Response cookies")
    content: HARContent = Field(default_factory=HARContent, description="Response content info")
    redirectURL: str = Field(default="", description="Redirect URL if any")


class HARTimings(BaseModel):
    """HAR timing information."""
    model_config = STRICT_CONFIG

    blocked: Optional[float] = Field(default=None, description="Time spent in blocked queue")
    dns: Optional[float] = Field(default=None, description="DNS resolution time")
    connect: Optional[float] = Field(default=None, description="Time to connect")
    send: Optional[float] = Field(default=None, description="Time to send request")
    wait: Optional[float] = Field(default=None, description="Time waiting for response")
    receive: Optional[float] = Field(default=None, description="Time to receive response")
    ssl: Optional[float] = Field(default=None, description="Time for SSL/TLS handshake")


class HARCache(BaseModel):
    """HAR cache information."""
    model_config = STRICT_CONFIG

    # These are optional fields that may appear in HAR cache objects
    beforeRequest: Optional[bool] = Field(default=None, description="Cache state before request")
    afterRequest: Optional[bool] = Field(default=None, description="Cache state after request")
    eTag: Optional[str] = Field(default=None, description="ETag value")
    hitCount: Optional[int] = Field(default=None, description="Cache hit count")


class MaliciousRequest(BaseModel):
    """HAR entry representing a potentially malicious request - simplified for LLM generation."""
    model_config = STRICT_CONFIG

    method: str = Field(description="HTTP method (GET, POST, etc.)")
    url: str = Field(description="Request URL")
    status: int = Field(description="HTTP response status code")
    entry_id: Optional[int] = Field(default=None, description="Entry ID/index in HAR file")

class PoCPayload(BaseModel):
    payload_mutation: str = Field(description="Explanation of the logic change (e.g., 'Changed price from 100 to -50')")
    curl_command: str = Field(description="The synthesized cURL command for reproduction")

class BLVFinding(BaseModel):
    """Business Logic Abuse vulnerability finding."""
    model_config = STRICT_CONFIG

    category: str = Field(description="OWASP BLA Category (misal: BLA6)")
    description: str = Field(description="Explanation/Justification why this is a BLV")
    evidence_entry_ids: List[int] = Field(description="HAR entry ID as evidence")
    # endpoint: List[MaliciousRequest] = Field(description="HAR entry request content")
    severity: str = Field(description="Severity: Low, Medium, High, Critical")
    reproduction_guide: PoCPayload


class ReasoningOutput(BaseModel):
    """Main output model for RAG-based vulnerability analysis."""
    model_config = STRICT_CONFIG

    business_flow: str = Field(description="Business flow reconstruction result")
    thought_process: List[str] = Field(default_factory=list, description="Chain-of-Thought Process")
    potential_vulnerabilities: List[BLVFinding] = Field(
        default_factory=list,
        description="List of potential BLA vulnerabilities found"
    )

