import json
import urllib.parse
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum

class EndpointType(Enum):
    UNIMPORTANT_STATIC_ASSET = "unimportant_static_asset"
    STATIC_ASSET = "static_asset"
    API_ENDPOINT = "api_endpoint"
    PAGE_REQUEST = "page_request"
    THIRD_PARTY = "third_party"
    AUTHENTICATION = "authentication"
    FORM_SUBMISSION = "form_submission"

@dataclass
class ParsedEndpoint:
    url: str
    method: str
    endpoint_type: EndpointType
    path: str
    query_params: Dict[str, str]
    headers: Dict[str, str]
    cookies: Dict[str, str]
    request_body: Optional[str]
    response_status: int
    response_headers: Dict[str, str]
    response_body: Optional[str]
    content_type: str
    is_sensitive: bool
    authentication_indicators: List[str]
    potential_parameters: List[str]
    # Additional fields for reasoning stage
    has_authorization_header: bool
    has_auth_cookies: bool
    reflects_input: bool
    form_fields: List[str]
    javascript_variables: List[str]
    # Helps in contextualization
    started_datetime: str        # original HAR timestamp
    request_index: int           # sequential index in HAR
    page_ref: Optional[str]      # HAR includes pageRef for grouping
    initiator: Optional[str]     # if har->`_initiator` exists (Chrome captures)

class ParserModule:
    RESPONSE_BODY_LIMIT = 2000  # Increased for better analysis
    MAX_PARAM_KEYS = 30  # Increased for more comprehensive parameter detection

    def __init__(self):
        self.third_party_domains = {
            'fonts.googleapis.com', 'fonts.gstatic.com', 'google.com',
            'googleapis.com', 'gstatic.com', 'googletagmanager.com',
            'google-analytics.com', 'doubleclick.net', 'facebook.com',
            'twitter.com', 'linkedin.com', 'instagram.com', 'cdnjs.cloudflare.com',
            'unpkg.com', 'jsdelivr.net'
        }

        self.third_party_indicators = {
            'bootstrap.bundle.min.js', 'bootstrap.min.js',
            'jquery.min.js', 'jquery.js', 'react.min.js', 'vue.min.js',
            '/vendor/', '/static/vendor/', '/libs/', '/node_modules/',
            '/assets/vendor/', '/cdn/', '/external/'
        }

        self.unimportant_static_extensions = {
            '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
            '.ico', '.woff', '.woff2', '.ttf', '.eot', '.pdf',
            '.mp4', '.mp3', '.avi', '.mov', '.zip', '.tar', '.gz'
        }

        self.important_static_extensions = {
            '.js', '.js.map', '.json', '.wasm', '.xml'
        }

        self.api_indicators = {
            '/api/', '/rest/', '/graphql', '/v1/', '/v2/', '/v3/', '/v4/',
            'api.', 'rest.', 'service.', '/ajax/', '/rpc/', '/ws/'
        }

        self.auth_indicators = {
            'authorization', 'bearer', 'token', 'session', 'auth',
            'login', 'logout', 'signin', 'signout', 'oauth', 'jwt'
        }

        self.sensitive_patterns = [
            'admin', 'login', 'password', 'token', 'key', 'secret',
            'private', 'internal', 'config', 'settings', 'user',
            'account', 'profile', 'payment', 'billing', 'dashboard',
            'management', 'control', 'panel'
        ]

    def parse_har_file(self, har_file_path: str) -> List[ParsedEndpoint]:
        """Parse HAR file and return list of structured endpoints"""
        print(f'[INFO] Parsing HAR file: {har_file_path}')

        try:
            with open(har_file_path, 'r', encoding='utf-8') as f:
                har_data = json.load(f)

            entries = har_data.get('log', {}).get('entries', [])
            parsed_endpoints = []

            print(f"[DEBUG] Total entries in HAR: {len(entries)}")

            for i, entry in enumerate(entries):
                try:
                    endpoint = self._parse_entry(entry, i)
                    if endpoint:
                        parsed_endpoints.append(endpoint)
                        if (i + 1) % 100 == 0:
                            print(f"[DEBUG] Parsed {i+1}/{len(entries)} entries")
                except Exception as e:
                    print(f"[ERROR] Failed to parse entry {i+1}: {e}")
                    continue

            print(f"[INFO] Successfully parsed {len(parsed_endpoints)} endpoints")
            return parsed_endpoints

        except Exception as e:
            print(f"[ERROR] Failed to parse HAR file: {e}")
            return []

    def _parse_entry(self, entry: Dict[str, Any], request_index: int) -> Optional[ParsedEndpoint]:
        """Parse single HAR entry into ParsedEndpoint"""
        try:
            request = entry.get('request', {})
            response = entry.get('response', {})

            # Extract contextual information
            started_datetime = entry.get('startedDateTime', '')
            page_ref = entry.get('pageref', None)  # HAR spec uses 'pageref'
            initiator = entry.get('_initiator', {}).get('type', None) if '_initiator' in entry else None

            # Basic request info
            url = request.get('url', '')
            method = request.get('method', 'GET').upper()

            if not url:
                return None

            parsed_url = urllib.parse.urlparse(url)

            # Query parameters
            query_params: Dict[str, str] = {}
            for param in request.get('queryString', []):
                name = param.get('name', '')
                if name:
                    query_params[name] = param.get('value', '')

            # Headers (preserve case for important ones, lowercase for lookup)
            headers: Dict[str, str] = {}
            for header in request.get('headers', []):
                name = header.get('name', '')
                value = header.get('value', '')
                if name:
                    # Keep original case for important headers
                    if name.lower() in ['authorization', 'cookie', 'x-requested-with', 'content-type']:
                        headers[name] = value
                    else:
                        headers[name.lower()] = value

            # Cookies
            cookies: Dict[str, str] = {}
            for cookie in request.get('cookies', []):
                name = cookie.get('name', '')
                if name:
                    cookies[name] = cookie.get('value', '')

            # Response headers
            response_headers: Dict[str, str] = {}
            for header in response.get('headers', []):
                name = header.get('name', '')
                value = header.get('value', '')
                if name:
                    response_headers[name.lower()] = value

            # Content type
            content_type = response_headers.get('content-type', '')
            if not content_type:
                content_type = response.get('content', {}).get('mimeType', '')
            content_type = content_type.split(';')[0].strip().lower()

            # Request body
            request_body = None
            if 'postData' in request:
                request_body = request['postData'].get('text', '')

            # Response body (with reasonable limit for analysis)
            response_body = None
            if 'content' in response and 'text' in response['content']:
                rb = response['content']['text']
                if isinstance(rb, str) and rb:
                    response_body = rb[:self.RESPONSE_BODY_LIMIT]

            # Classify endpoint type
            endpoint_type = self._classify_endpoint(url, method, content_type, headers)

            # Authentication analysis
            auth_indicators = self._detect_auth_indicators(url, headers, cookies)
            has_authorization_header = any('authorization' in h.lower() for h in headers.keys())
            has_auth_cookies = any(self._is_auth_cookie(name) for name in cookies.keys())

            # Parameter extraction
            potential_params = self._extract_potential_parameters(
                url, headers, request_body, response_body
            )

            # Form field extraction
            form_fields = self._extract_form_fields(response_body)

            # JavaScript variable extraction
            js_variables = self._extract_js_variables(response_body)

            # Input reflection detection
            reflects_input = self._detect_input_reflection(
                query_params, request_body, response_body
            )

            # Sensitivity check
            is_sensitive = self._is_sensitive_endpoint(url, headers, cookies, auth_indicators)

            return ParsedEndpoint(
                url=url,
                method=method,
                endpoint_type=endpoint_type,
                path=parsed_url.path,
                query_params=query_params,
                headers=headers,
                cookies=cookies,
                request_body=request_body,
                response_status=response.get('status', 0),
                response_headers=response_headers,
                response_body=response_body,
                content_type=content_type,
                is_sensitive=is_sensitive,
                authentication_indicators=auth_indicators,
                potential_parameters=potential_params,
                has_authorization_header=has_authorization_header,
                has_auth_cookies=has_auth_cookies,
                reflects_input=reflects_input,
                form_fields=form_fields,
                javascript_variables=js_variables,
                started_datetime=started_datetime,
                request_index=request_index,
                page_ref=page_ref,
                initiator=initiator
            )

        except Exception as e:
            print(f"[ERROR] Error parsing entry: {e}")
            return None

    def _classify_endpoint(self, url: str, method: str, content_type: str, headers: Dict[str, str]) -> EndpointType:
        """Classify endpoint based on URL patterns and characteristics"""
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()

        # Third party
        if any(tp_domain in domain for tp_domain in self.third_party_domains):
            return EndpointType.THIRD_PARTY
        if any(tp_path in path for tp_path in self.third_party_indicators):
            return EndpointType.THIRD_PARTY

        # Unimportant static assets
        if any(path.endswith(ext) for ext in self.unimportant_static_extensions):
            return EndpointType.UNIMPORTANT_STATIC_ASSET

        # Important static assets (JS, JSON, etc.)
        if any(path.endswith(ext) for ext in self.important_static_extensions):
            return EndpointType.STATIC_ASSET

        # API endpoints
        if any(indicator in url.lower() for indicator in self.api_indicators):
            return EndpointType.API_ENDPOINT

        # Authentication related
        if any(indicator in url.lower() for indicator in self.auth_indicators):
            return EndpointType.AUTHENTICATION

        # Form submissions
        if method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            if ('form' in content_type or 'x-www-form-urlencoded' in content_type or
                'multipart/form-data' in content_type):
                return EndpointType.FORM_SUBMISSION

        # Default to page request (HTML pages, SPA routes, etc.)
        return EndpointType.PAGE_REQUEST

    def _detect_auth_indicators(self, url: str, headers: Dict[str, str], cookies: Dict[str, str]) -> List[str]:
        """Detect authentication-related indicators"""
        indicators = []

        # URL-based indicators
        url_lower = url.lower()
        for auth_term in self.auth_indicators:
            if auth_term in url_lower:
                indicators.append(f"url_contains_{auth_term}")

        # Header-based indicators
        for header_name, header_value in headers.items():
            header_lower = header_name.lower()
            if 'authorization' in header_lower:
                indicators.append("authorization_header")
            if isinstance(header_value, str):
                if 'bearer' in header_value.lower():
                    indicators.append("bearer_token")
                if 'basic' in header_value.lower():
                    indicators.append("basic_auth")

        # Cookie-based indicators
        for cookie_name in cookies.keys():
            if self._is_auth_cookie(cookie_name):
                indicators.append(f"auth_cookie_{cookie_name}")

        return indicators

    def _is_auth_cookie(self, cookie_name: str) -> bool:
        """Check if cookie name indicates authentication"""
        cookie_lower = cookie_name.lower()
        auth_cookie_patterns = [
            'session', 'auth', 'token', 'sid', 'jwt', 'access',
            'refresh', 'login', 'user', 'csrf', 'xsrf'
        ]
        return any(pattern in cookie_lower for pattern in auth_cookie_patterns)

    def _extract_potential_parameters(self, url: str, headers: Dict[str, str],
                                    request_body: Optional[str], response_body: Optional[str]) -> List[str]:
        """Extract potential parameters for testing"""
        params = set()

        # From URL query parameters
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        params.update(query_params.keys())

        # From request body
        if request_body:
            params.update(self._extract_params_from_body(request_body))

        # From response body (API fields, form inputs)
        if response_body:
            params.update(self._extract_params_from_response(response_body))

        # Limit and sort
        sorted_params = sorted(list(params))
        return sorted_params[:self.MAX_PARAM_KEYS]

    def _extract_params_from_body(self, body: str) -> set:
        """Extract parameters from request body"""
        params = set()
        try:
            body = body.strip()
            if body.startswith('{') or body.startswith('['):
                # JSON body
                json_data = json.loads(body)
                params.update(self._extract_json_keys(json_data))
            elif '=' in body:
                # Form-encoded body
                form_data = urllib.parse.parse_qs(body)
                params.update(form_data.keys())
        except Exception:
            pass
        return params

    def _extract_params_from_response(self, response_body: str) -> set:
        """Extract potential parameters from response body"""
        params = set()
        try:
            # HTML form inputs
            input_patterns = [
                r'name=["\']([^"\']+)["\']',
                r'id=["\']([^"\']+)["\']',
                r'data-[a-zA-Z-]+=["\']([^"\']+)["\']'
            ]

            # JSON API fields
            json_patterns = [
                r'"([a-zA-Z_][a-zA-Z0-9_]*)":\s*["\'{[]',
                r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']:\s*["\'{[]'
            ]

            all_patterns = input_patterns + json_patterns

            for pattern in all_patterns:
                matches = re.findall(pattern, response_body, re.IGNORECASE)
                for match in matches:
                    if len(match) > 1 and len(match) < 50:  # Reasonable parameter name length
                        params.add(match)

        except Exception:
            pass
        return params

    def _extract_form_fields(self, response_body: Optional[str]) -> List[str]:
        """Extract form field names from HTML response"""
        if not response_body:
            return []

        form_fields = set()
        try:
            # Extract input, select, textarea names
            patterns = [
                r'<input[^>]+name=["\']([^"\']+)["\']',
                r'<select[^>]+name=["\']([^"\']+)["\']',
                r'<textarea[^>]+name=["\']([^"\']+)["\']'
            ]

            for pattern in patterns:
                matches = re.findall(pattern, response_body, re.IGNORECASE)
                form_fields.update(matches)

        except Exception:
            pass

        return sorted(list(form_fields))

    def _extract_js_variables(self, response_body: Optional[str]) -> List[str]:
        """Extract JavaScript variable names that might be interesting"""
        if not response_body:
            return []

        js_vars = set()
        try:
            # Look for common JS patterns
            patterns = [
                r'var\s+([a-zA-Z_$][a-zA-Z0-9_$]*)',
                r'let\s+([a-zA-Z_$][a-zA-Z0-9_$]*)',
                r'const\s+([a-zA-Z_$][a-zA-Z0-9_$]*)',
                r'window\.([a-zA-Z_$][a-zA-Z0-9_$]*)',
                r'\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=',
            ]

            for pattern in patterns:
                matches = re.findall(pattern, response_body)
                for match in matches:
                    if len(match) > 2 and len(match) < 30:
                        js_vars.add(match)

        except Exception:
            pass

        return sorted(list(js_vars))[:20]  # Limit to most relevant

    def _detect_input_reflection(self, query_params: Dict[str, str],
                               request_body: Optional[str], response_body: Optional[str]) -> bool:
        """Detect if user input is reflected in response"""
        if not response_body:
            return False

        try:
            # Check query parameters
            for param_name, param_value in query_params.items():
                if param_value and len(param_value) > 3:
                    if param_value in response_body:
                        return True

            # Check request body parameters
            if request_body:
                body_params = self._extract_params_from_body(request_body)
                # This is simplified - in real implementation you'd parse the actual values
                for param in body_params:
                    if param in response_body:
                        return True

        except Exception:
            pass

        return False

    def _extract_json_keys(self, data: Any, prefix: str = '') -> List[str]:
        """Recursively extract keys from JSON data"""
        keys: List[str] = []
        if isinstance(data, dict):
            for k, v in data.items():
                full_key = f"{prefix}.{k}" if prefix else k
                keys.append(full_key)
                if isinstance(v, (dict, list)) and len(keys) < 100:  # Prevent infinite recursion
                    keys.extend(self._extract_json_keys(v, full_key))
        elif isinstance(data, list) and data and len(keys) < 100:
            keys.extend(self._extract_json_keys(data[0], prefix))
        return keys

    def _is_sensitive_endpoint(self, url: str, headers: Dict[str, str],
                             cookies: Dict[str, str], auth_indicators: List[str]) -> bool:
        """Determine if endpoint handles sensitive data"""
        url_lower = url.lower()

        # Check URL patterns
        if any(pattern in url_lower for pattern in self.sensitive_patterns):
            return True

        # Check for authentication indicators
        if auth_indicators:
            return True

        # Check for sensitive cookies
        for cookie_name in cookies.keys():
            if any(pattern in cookie_name.lower() for pattern in self.sensitive_patterns):
                return True

        return False

    def export_full_json(self, endpoints: List[ParsedEndpoint], output_file: str):
        """Export all endpoints with full details for reasoning stage, with deduplicated stores"""
        # Filter out only truly unimportant assets
        filtered_endpoints = [
            ep for ep in endpoints
            if ep.endpoint_type != EndpointType.UNIMPORTANT_STATIC_ASSET
        ]

        # Initialize deduplication stores
        headers_store = {}
        cookies_store = {}
        response_headers_store = {}

        headers_map = {}  # hash -> id
        cookies_map = {}  # hash -> id
        response_headers_map = {}  # hash -> id

        next_hid = 1
        next_cid = 1
        next_rhid = 1

        def get_or_create_id(data_dict: dict, store: dict, id_map: dict, prefix: str, next_id: int) -> tuple:
            """Get existing ID or create new one for data dict"""
            if not data_dict:
                return None, next_id

            # Create hash key for deduplication
            hash_key = json.dumps(data_dict, sort_keys=True, ensure_ascii=False)

            if hash_key in id_map:
                return id_map[hash_key], next_id

            # Create new ID
            new_id = f"{prefix}_{next_id}"
            store[new_id] = data_dict
            id_map[hash_key] = new_id
            return new_id, next_id + 1

        # Convert to serializable format with deduplication
        serializable_endpoints = []

        for ep in filtered_endpoints:
            # Get or create IDs for headers, cookies, response_headers
            headers_ref, next_hid = get_or_create_id(
                ep.headers, headers_store, headers_map, "hdr", next_hid
            )
            cookies_ref, next_cid = get_or_create_id(
                ep.cookies, cookies_store, cookies_map, "ck", next_cid
            )
            response_headers_ref, next_rhid = get_or_create_id(
                ep.response_headers, response_headers_store, response_headers_map, "rhdr", next_rhid
            )

            # Create endpoint dict without the heavy data
            ep_dict = {
                'url': ep.url,
                'method': ep.method,
                'endpoint_type': ep.endpoint_type.value,
                'path': ep.path,
                'query_params': ep.query_params,
                'headers_ref': headers_ref,
                'cookies_ref': cookies_ref,
                'request_body': ep.request_body,
                'response_status': ep.response_status,
                'response_headers_ref': response_headers_ref,
                'response_body': ep.response_body,  # Keep inline for XSS analysis
                'content_type': ep.content_type,
                'is_sensitive': ep.is_sensitive,
                'authentication_indicators': ep.authentication_indicators,
                'potential_parameters': ep.potential_parameters,
                'has_authorization_header': ep.has_authorization_header,
                'has_auth_cookies': ep.has_auth_cookies,
                'reflects_input': ep.reflects_input,
                'form_fields': ep.form_fields,
                'javascript_variables': ep.javascript_variables
            }

            serializable_endpoints.append(ep_dict)

        # Create summary statistics
        summary = {
            'total_endpoints': len(serializable_endpoints),
            'by_type': {},
            'by_method': {},
            'sensitive_count': sum(1 for ep in filtered_endpoints if ep.is_sensitive),
            'with_auth': sum(1 for ep in filtered_endpoints if ep.authentication_indicators),
            'reflects_input': sum(1 for ep in filtered_endpoints if ep.reflects_input),
            'deduplication_stats': {
                'unique_headers': len(headers_store),
                'unique_cookies': len(cookies_store),
                'unique_response_headers': len(response_headers_store)
            }
        }

        # Count by type and method
        for ep in filtered_endpoints:
            ep_type = ep.endpoint_type.value
            summary['by_type'][ep_type] = summary['by_type'].get(ep_type, 0) + 1
            summary['by_method'][ep.method] = summary['by_method'].get(ep.method, 0) + 1

        # Final output structure with stores at top level
        output_data = {
            'summary': summary,
            'headers_store': headers_store,
            'cookies_store': cookies_store,
            'response_headers_store': response_headers_store,
            'endpoints': serializable_endpoints
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, ensure_ascii=False, indent=2)

        print(f"[INFO] Exported {len(serializable_endpoints)} endpoints to {output_file}")
        print(f"[INFO] Summary: {summary['by_type']}")
        print(f"[INFO] Deduplication: {len(headers_store)} unique headers, {len(cookies_store)} unique cookies, {len(response_headers_store)} unique response headers")

if __name__ == "__main__":
    parser = ParserModule()
    filename = input('Enter filename (hars/<name>.har): ').strip()

    endpoints = parser.parse_har_file(f'hars/{filename}.har')

    print(f"\n=== PARSING SUMMARY ===")
    print(f"Total endpoints parsed: {len(endpoints)}")

    # Show breakdown by type
    for endpoint_type in EndpointType:
        count = sum(1 for ep in endpoints if ep.endpoint_type == endpoint_type)
        if count > 0:
            print(f"{endpoint_type.value}: {count}")

    # Export full details with deduplication
    output_path = f'parsed_hars/{filename}.json'
    parser.export_full_json(endpoints, output_path)