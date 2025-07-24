import json
import urllib.parse
from typing import List, Dict, Any, Optional

class ParserModule:
    def __init__(self):
        self.static_extensions = {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.map'}

        # Domains/hosts yang biasanya third-party/tracking
        self.third_party_domains = {
            'fonts.googleapis.com',
            'fonts.gstatic.com',
            'googletagmanager.com',
            'google-analytics.com',
            'doubleclick.net',
            'facebook.com',
            'twitter.com',
            'linkedin.com',
            'cdnjs.cloudflare.com',
            'unpkg.com',
            'jsdelivr.net'
        }

        # Path patterns yang biasanya static/tracking
        self.static_path_patterns = {
            '/css', '/js', '/fonts', '/images', '/img', '/assets', '/static',
            '/gtag', '/analytics', '/tracking', '/pixel', '/beacon'
        }

        # Content types yang nggak relevan untuk security testing
        self.irrelevant_content_types = {
            'text/css', 'text/javascript', 'application/javascript',
            'image/', 'font/', 'audio/', 'video/',
            'text/plain', 'application/octet-stream'
        }

    def parse_har_file(self, har_path: str) -> List[Dict[str, Any]]:
        """Parse HAR file and extract relevant HTTP interactions"""
        with open(har_path, 'r', encoding='utf-8') as f:
            har_data = json.load(f)

        endpoints = []
        for entry in har_data['log']['entries']:
            request = entry['request']
            response = entry['response']

            # Filter out static assets and irrelevant requests
            if self._is_relevant_request(request, response):
                endpoint_data = self._extract_endpoint_data(request, response)
                if endpoint_data:
                    endpoints.append(endpoint_data)

        return endpoints

    def _is_relevant_request(self, request: Dict, response: Dict) -> bool:
        """Enhanced filtering for relevant requests only"""
        url = request['url']
        method = request['method']

        parsed_url = urllib.parse.urlparse(url)
        host = parsed_url.netloc.lower()
        path = parsed_url.path.lower()

        # 1. Skip third-party domains
        if any(domain in host for domain in self.third_party_domains):
            return False

        # 2. Skip static file extensions
        if any(path.endswith(ext) for ext in self.static_extensions):
            return False

        # 3. Skip static path patterns
        if any(pattern in path for pattern in self.static_path_patterns):
            return False

        # 4. Check response content-type
        response_content_type = self._get_response_content_type(response)
        if response_content_type:
            if any(irrelevant in response_content_type for irrelevant in self.irrelevant_content_types):
                return False

        # 5. Always include state-changing methods
        if method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            return True

        # 6. For GET requests, be more selective
        if method == 'GET':
            # Include if it looks like API endpoint
            if any(api_indicator in path for api_indicator in ['/api/', '/v1/', '/v2/', '/graphql', '/rest/']):
                return True

            # Include if it has meaningful query parameters (not just tracking)
            if parsed_url.query:
                query_params = urllib.parse.parse_qs(parsed_url.query)
                # Skip common tracking parameters
                tracking_params = {'utm_source', 'utm_medium', 'utm_campaign', 'fbclid', 'gclid', '_ga', '_gid'}
                meaningful_params = set(query_params.keys()) - tracking_params
                if meaningful_params:
                    return True

            # Include if response indicates dynamic content
            if response_content_type and 'application/json' in response_content_type:
                return True

            # Include if it's an error response (might reveal info)
            if response['status'] >= 400:
                return True

        return False

    def _get_response_content_type(self, response: Dict) -> Optional[str]:
        """Extract content-type from response headers"""
        for header in response.get('headers', []):
            if header['name'].lower() == 'content-type':
                return header['value'].lower()
        return None

    def _extract_endpoint_data(self, request: Dict, response: Dict) -> Optional[Dict[str, Any]]:
        """Extract structured data from request-response pair"""
        try:
            parsed_url = urllib.parse.urlparse(request['url'])

            # Extract parameters
            params = self._extract_parameters(request, parsed_url)

            # Extract relevant headers
            relevant_headers = self._extract_relevant_headers(request['headers'])

            # Extract request body
            request_body = self._extract_request_body(request)

            # Extract response info
            response_info = self._extract_response_info(response)

            # Determine context
            context = self._determine_context(request, response, parsed_url)

            return {
                'method': request['method'],
                'url': parsed_url.path,
                'full_url': request['url'],
                'headers': relevant_headers,
                'request_body': request_body,
                'response_status': response['status'],
                'response_body_snippet': response_info['body_snippet'],
                'response_headers': response_info['headers'],
                'params': params,
                'context': context,
                'timestamp': request.get('timestamp', '')
            }
        except Exception as e:
            print(f"Error parsing request: {e}")
            return None

    def _extract_parameters(self, request: Dict, parsed_url) -> Dict[str, List[str]]:
        """Extract query, path, and body parameters"""
        params = {
            'query': [],
            'path': [],
            'body': []
        }

        # Query parameters (exclude tracking params)
        if parsed_url.query:
            query_params = urllib.parse.parse_qs(parsed_url.query)
            tracking_params = {'utm_source', 'utm_medium', 'utm_campaign', 'fbclid', 'gclid', '_ga', '_gid', 'ref', 'source'}
            meaningful_params = [key for key in query_params.keys() if key not in tracking_params]
            params['query'] = meaningful_params

        # Path parameters (basic detection for REST-style paths)
        path_segments = [seg for seg in parsed_url.path.split('/') if seg]
        params['path'] = [seg for seg in path_segments if seg.isdigit() or len(seg) > 10]  # Heuristic for IDs

        # Body parameters
        if request.get('postData'):
            post_data = request['postData']
            if post_data.get('mimeType') == 'application/json':
                try:
                    body_json = json.loads(post_data.get('text', '{}'))
                    params['body'] = self._extract_json_keys(body_json)
                except:
                    pass
            elif post_data.get('mimeType') == 'application/x-www-form-urlencoded':
                if post_data.get('params'):
                    params['body'] = [param['name'] for param in post_data['params']]

        return params

    def _extract_json_keys(self, obj, prefix='') -> List[str]:
        """Recursively extract keys from JSON object"""
        keys = []
        if isinstance(obj, dict):
            for key, value in obj.items():
                full_key = f"{prefix}.{key}" if prefix else key
                keys.append(full_key)
                if isinstance(value, (dict, list)):
                    keys.extend(self._extract_json_keys(value, full_key))
        elif isinstance(obj, list) and obj:
            keys.extend(self._extract_json_keys(obj[0], f"{prefix}[0]"))
        return keys

    def _extract_relevant_headers(self, headers: List[Dict]) -> Dict[str, str]:
        """Extract security-relevant headers"""
        relevant = ['authorization', 'content-type', 'x-api-key', 'x-csrf-token', 'cookie']
        result = {}

        for header in headers:
            name = header['name'].lower()
            if name in relevant:
                result[name] = header['value']

        return result

    def _extract_request_body(self, request: Dict) -> Optional[Any]:
        """Extract and parse request body"""
        if not request.get('postData'):
            return None

        post_data = request['postData']
        mime_type = post_data.get('mimeType', '')
        text = post_data.get('text', '')

        if 'application/json' in mime_type:
            try:
                return json.loads(text)
            except:
                return text
        elif 'application/x-www-form-urlencoded' in mime_type:
            return dict(urllib.parse.parse_qsl(text))
        else:
            return text[:200] if text else None  # Truncate for brevity

    def _extract_response_info(self, response: Dict) -> Dict[str, Any]:
        """Extract relevant response information"""
        content = response.get('content', {})
        text = content.get('text', '')

        # Extract snippet (first 500 chars or error messages)
        snippet = None
        if text:
            if response['status'] >= 400:  # Error responses
                snippet = text[:500]
            elif 'application/json' in content.get('mimeType', ''):
                try:
                    json_data = json.loads(text)
                    snippet = json.dumps(json_data, indent=2)[:500]
                except:
                    snippet = text[:200]
            else:
                snippet = text[:200]

        # Extract relevant response headers
        relevant_headers = {}
        for header in response.get('headers', []):
            name = header['name'].lower()
            if name in ['content-type', 'set-cookie', 'location', 'x-frame-options', 'x-xss-protection']:
                relevant_headers[name] = header['value']

        return {
            'body_snippet': snippet,
            'headers': relevant_headers
        }

    def _determine_context(self, request: Dict, response: Dict, parsed_url) -> str:
        """Determine request context for security analysis"""
        context_hints = []

        # Authentication context
        auth_headers = ['authorization', 'cookie', 'x-api-key']
        has_auth = any(h['name'].lower() in auth_headers for h in request.get('headers', []))

        if not has_auth:
            context_hints.append("public endpoint")
        else:
            context_hints.append("authenticated endpoint")

        # API context
        if any(api_indicator in parsed_url.path for api_indicator in ['/api/', '/v1/', '/v2/', '/graphql', '/rest/']):
            context_hints.append("API endpoint")

        # Error context
        if response['status'] >= 400:
            context_hints.append(f"error response ({response['status']})")

        # Method context
        if request['method'] in ['POST', 'PUT', 'DELETE', 'PATCH']:
            context_hints.append("state-changing operation")

        return ", ".join(context_hints)

    def filter_endpoints(self, endpoints: List[Dict[str, Any]],
                        methods: List[str] = None,
                        min_priority: str = None) -> List[Dict[str, Any]]:
        """Filter endpoints based on criteria"""
        filtered = endpoints

        if methods:
            filtered = [e for e in filtered if e['method'] in methods]

        if min_priority:
            priority_order = {'low': 0, 'medium': 1, 'high': 2}
            min_score = priority_order.get(min_priority, 0)
            filtered = [e for e in filtered if priority_order.get(e.get('priority', 'low'), 0) >= min_score]

        return filtered

    def export_endpoints(self, endpoints: List[Dict[str, Any]], output_path: str):
        """Export endpoints to JSON file"""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(endpoints, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
  filename = 'har_example'
  parser = ParserModule()
  endpoints = parser.parse_har_file('../hars/' + filename + '.har')
  filtered_endpoints = parser.filter_endpoints(endpoints)
  parser.export_endpoints(filtered_endpoints, '../json/' + filename + '.json')