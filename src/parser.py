import json
import urllib.parse
from typing import List, Dict, Any, Optional

import json
import urllib.parse
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
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

class ParserModule:
    def __init__(self):
        self.third_party_domains = {
            'fonts.googleapis.com', 'fonts.gstatic.com', 'google.com',
            'googleapis.com', 'gstatic.com', 'googletagmanager.com',
            'google-analytics.com', 'doubleclick.net', 'facebook.com',
            'twitter.com', 'linkedin.com', 'instagram.com',
        }

        self.third_party_indicators = {
            'bootstrap.bundle.min.js', 'bootstrap.min.js',
            'jquery.min.js', 'jquery.js',
            '/vendor/', '/static/vendor/', '/libs/', '/node_modules/', '/assets/vendor/'
        }

        self.unimportant_static_extensions = {
            '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
            '.ico', '.woff', '.woff2', '.ttf', '.eot', '.pdf'
        }

        self.important_static_extensions = {
            '.js', '.js.map', '.json', '.wasm'
        }

        self.api_indicators = {
            '/api/', '/rest/', '/graphql', '/v1/', '/v2/', '/v3/',
            'api.', 'rest.', 'service.'
        }

        self.auth_indicators = {
            'authorization', 'bearer', 'token', 'session', 'auth',
            'login', 'logout', 'signin', 'signout', 'oauth'
        }

    def parse_har_file(self, har_file_path: str) -> List[ParsedEndpoint]:
        print('har_file_path:', har_file_path)
        """Parse HAR file dan return list of structured endpoints"""
        try:
            with open(har_file_path, 'r', encoding='utf-8') as f:
                har_data = json.load(f)

            entries = har_data.get('log', {}).get('entries', [])
            parsed_endpoints = []

            print(f"[DEBUG] Total entries in HAR: {len(entries)}")

            for i, entry in enumerate(entries):
                try:
                    endpoint = self._parse_entry(entry)
                    if endpoint:
                        parsed_endpoints.append(endpoint)
                        print(f"[DEBUG] Parsed entry {i+1}: {endpoint.method} {endpoint.url}")
                    else:
                        print(f"[DEBUG] Skipped entry {i+1}")
                except Exception as e:
                    print(f"[ERROR] Failed to parse entry {i+1}: {e}")
                    continue

            print(f"[DEBUG] Successfully parsed {len(parsed_endpoints)} endpoints")
            return parsed_endpoints

        except Exception as e:
            print(f"[ERROR] Failed to parse HAR file: {e}")
            return []

    def _parse_entry(self, entry: Dict[str, Any]) -> Optional[ParsedEndpoint]:
        """Parse single HAR entry into ParsedEndpoint"""
        try:
            request = entry.get('request', {})
            response = entry.get('response', {})

            # Extract basic request info
            url = request.get('url', '')
            method = request.get('method', 'GET').upper()

            if not url:
                return None

            parsed_url = urllib.parse.urlparse(url)

            # Extract query parameters
            query_params = {}
            for param in request.get('queryString', []):
                query_params[param.get('name', '')] = param.get('value', '')

            # Extract headers
            headers = {}
            for header in request.get('headers', []):
                headers[header.get('name', '').lower()] = header.get('value', '')

            # Extract cookies
            cookies = {}
            for cookie in request.get('cookies', []):
                cookies[cookie.get('name', '')] = cookie.get('value', '')

            # Extract response headers
            response_headers = {}
            for header in response.get('headers', []):
                response_headers[header.get('name', '').lower()] = header.get('value', '')

            # Determine content type
            content_type = response_headers.get('content-type', '').split(';')[0].strip()

            # Extract request body
            request_body = None
            if 'postData' in request:
                request_body = request['postData'].get('text', '')

            # Extract response body (truncated for large responses)
            response_body = None
            if 'content' in response and 'text' in response['content']:
                response_body = response['content']['text'][:5000]  # Limit to 5KB

            # Classify endpoint type
            endpoint_type = self._classify_endpoint(url, method, content_type, headers)

            # Check for authentication indicators
            auth_indicators = self._detect_auth_indicators(url, headers, cookies)

            # Extract potential parameters for testing
            potential_params = self._extract_potential_parameters(
                url, headers, request_body, response_body
            )

            # Determine if endpoint is sensitive
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
                potential_parameters=potential_params
            )

        except Exception as e:
            print(f"[ERROR] Error parsing entry: {e}")
            return None

    def _classify_endpoint(self, url: str, method: str, content_type: str, headers: Dict[str, str]) -> EndpointType:
        """Classify endpoint berdasarkan karakteristiknya"""
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()

        # Check if third party
        if any(tp_domain in domain for tp_domain in self.third_party_domains):
            return EndpointType.THIRD_PARTY
        if any(tp_path in path for tp_path in self.third_party_indicators):
            return EndpointType.THIRD_PARTY

        # Check if unimportant static asset
        if any(path.endswith(ext) for ext in self.unimportant_static_extensions):
            return EndpointType.UNIMPORTANT_STATIC_ASSET

        # Check if static asset
        if any(path.endswith(ext) for ext in self.important_static_extensions):
            return EndpointType.STATIC_ASSET

        # Check if API endpoint
        if any(indicator in url.lower() for indicator in self.api_indicators):
            return EndpointType.API_ENDPOINT

        # Check if authentication related
        if any(indicator in url.lower() for indicator in self.auth_indicators):
            return EndpointType.AUTHENTICATION

        # Check if form submission
        if method in ['POST', 'PUT', 'PATCH'] and 'form' in content_type:
            return EndpointType.FORM_SUBMISSION

        # Default to page request
        return EndpointType.PAGE_REQUEST

    def _detect_auth_indicators(self, url: str, headers: Dict[str, str], cookies: Dict[str, str]) -> List[str]:
        """Detect authentication indicators"""
        indicators = []

        # Check URL
        url_lower = url.lower()
        for auth_term in self.auth_indicators:
            if auth_term in url_lower:
                indicators.append(f"url_contains_{auth_term}")

        # Check headers
        for header_name, header_value in headers.items():
            if 'authorization' in header_name.lower():
                indicators.append("authorization_header")
            if 'bearer' in header_value.lower():
                indicators.append("bearer_token")

        # Check cookies
        for cookie_name in cookies.keys():
            cookie_lower = cookie_name.lower()
            if any(term in cookie_lower for term in ['session', 'auth', 'token', 'sid']):
                indicators.append(f"auth_cookie_{cookie_name}")

        return indicators

    def _extract_potential_parameters(self, url: str, headers: Dict[str, str],
                                    request_body: Optional[str], response_body: Optional[str]) -> List[str]:
        """Extract potential parameters untuk testing"""
        params = set()

        # Extract from URL query parameters
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        params.update(query_params.keys())

        # Extract from request body (JSON/form data)
        if request_body:
            try:
                if request_body.startswith('{'):
                    json_data = json.loads(request_body)
                    params.update(self._extract_json_keys(json_data))
                elif '=' in request_body:
                    form_data = urllib.parse.parse_qs(request_body)
                    params.update(form_data.keys())
            except:
                pass

        # Extract from response body (look for input names, API fields)
        if response_body:
            # Simple regex patterns untuk common parameter names
            import re
            patterns = [
                r'name=["\']([^"\']+)["\']',
                r'id=["\']([^"\']+)["\']',
                r'"([a-zA-Z_][a-zA-Z0-9_]*)":\s*["\'{]',
            ]

            for pattern in patterns:
                matches = re.findall(pattern, response_body)
                params.update(matches)

        return list(params)[:20]  # Limit to 20 parameters

    def _extract_json_keys(self, data: Any, prefix: str = '') -> List[str]:
        """Recursively extract keys from JSON data"""
        keys = []
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                keys.append(full_key)
                if isinstance(value, (dict, list)):
                    keys.extend(self._extract_json_keys(value, full_key))
        elif isinstance(data, list) and data:
            keys.extend(self._extract_json_keys(data[0], prefix))
        return keys

    def _is_sensitive_endpoint(self, url: str, headers: Dict[str, str],
                             cookies: Dict[str, str], auth_indicators: List[str]) -> bool:
        """Determine if endpoint potentially sensitive"""
        sensitive_patterns = [
            'admin', 'login', 'password', 'token', 'key', 'secret',
            'private', 'internal', 'config', 'settings', 'user',
            'account', 'profile', 'payment', 'billing'
        ]

        url_lower = url.lower()

        # Check URL for sensitive patterns
        if any(pattern in url_lower for pattern in sensitive_patterns):
            return True

        # Check if has authentication indicators
        if auth_indicators:
            return True

        # Check if has sensitive cookies
        for cookie_name in cookies.keys():
            if any(pattern in cookie_name.lower() for pattern in sensitive_patterns):
                return True

        return False

    def export_to_json(self, endpoints: List[ParsedEndpoint], output_file: str):
        """Export parsed endpoints to JSON file"""
        data = []

        for endpoint in endpoints:
            if endpoint.endpoint_type == EndpointType.THIRD_PARTY or endpoint.endpoint_type == EndpointType.UNIMPORTANT_STATIC_ASSET:
                continue

            data.append({
                'url': endpoint.url,
                'method': endpoint.method,
                'endpoint_type': endpoint.endpoint_type.value,
                'path': endpoint.path,
                'query_params': endpoint.query_params,
                'headers': endpoint.headers,
                'cookies': endpoint.cookies,
                'request_body': endpoint.request_body,
                'response_status': endpoint.response_status,
                'response_headers': endpoint.response_headers,
                'response_body': endpoint.response_body[:500] if endpoint.response_body else None,
                'content_type': endpoint.content_type,
                'is_sensitive': endpoint.is_sensitive,
                'authentication_indicators': endpoint.authentication_indicators,
                'potential_parameters': endpoint.potential_parameters
            })

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print(f"[INFO] Exported {len(data)} endpoints to {output_file}")

if __name__ == "__main__":
    PM = ParserModule()

    filename = input('Enter filename (hars/<name>.har): ')
    endpoints = PM.parse_har_file(f'hars/{filename}.har')

    # Print summary
    print(f"\n=== PARSING SUMMARY ===")
    print(f"Total endpoints parsed: {len(endpoints)}")

    for endpoint_type in EndpointType:
        count = sum(1 for ep in endpoints if ep.endpoint_type == endpoint_type)
        if count > 0:
            print(f"{endpoint_type.value}: {count}")

    # Print detailed info for each endpoint
    print(f"\n=== DETAILED ENDPOINTS ===")
    for i, endpoint in enumerate(endpoints, 1):
        print(f"\n{i}. {endpoint.method} {endpoint.url}")
        print(f"   Type: {endpoint.endpoint_type.value}")
        print(f"   Status: {endpoint.response_status}")
        print(f"   Content-Type: {endpoint.content_type}")
        print(f"   Sensitive: {endpoint.is_sensitive}")
        if endpoint.authentication_indicators:
            print(f"   Auth Indicators: {endpoint.authentication_indicators}")
        if endpoint.potential_parameters:
            print(f"   Potential Params: {endpoint.potential_parameters[:5]}")

    # Export to JSON
    PM.export_to_json(endpoints, f'parsed_hars/{filename}.json')