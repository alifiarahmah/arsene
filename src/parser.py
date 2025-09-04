import json
import urllib.parse
import re
from typing import Counter, Dict, List, Any, Optional, Tuple
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
    MAX_PARAM_KEYS = 20
    RESPONSE_BODY_SNIFF_LIMIT = 1200
    MAX_GROUPS = 250
    SHARD_SIZE = 250
    INCLUDE_STATIC_ASSETS = False

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
                        if (i + 1) % 50 == 0:
                            print(f"[DEBUG] Parsed up to entry {i+1}")
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

            # basic request info
            url = request.get('url', '')
            method = request.get('method', 'GET').upper()

            if not url:
                return None

            parsed_url = urllib.parse.urlparse(url)

            # query parameters
            query_params: Dict[str, str] = {}
            for param in request.get('queryString', []):
                name = param.get('name', '')
                if name:
                    query_params[name] = param.get('value', '')

            # headers
            headers: Dict[str, str] = {}
            for header in request.get('headers', []):
                name = header.get('name', '')
                if name:
                    headers[name.lower()] = header.get('value', '')

            # cookies
            cookies: Dict[str, str] = {}
            for cookie in request.get('cookies', []):
                name = cookie.get('name', '')
                if name:
                    cookies[name] = cookie.get('value', '')

            # response headers
            response_headers: Dict[str, str] = {}
            for header in response.get('headers', []):
                name = header.get('name', '')
                if name:
                    response_headers[name.lower()] = header.get('value', '')

            # determine content type
            content_type = response_headers.get('content-type', '')
            if not content_type:
                content_type = response.get('content', {}).get('mimeType', '')
            content_type = content_type.split(';')[0].strip().lower()

            # request body
            request_body = None
            if 'postData' in request:
                request_body = request['postData'].get('text', '')

            # response body (truncated for large responses)
            response_body = None
            if 'content' in response and 'text' in response['content']:
                rb = response['content']['text']
                if isinstance(rb, str) and rb:
                    response_body = rb[: self.RESPONSE_BODY_SNIFF_LIMIT]

            # classify endpoint type
            endpoint_type = self._classify_endpoint(url, method, content_type, headers)

            # check for authentication indicators
            auth_indicators = self._detect_auth_indicators(url, headers, cookies)

            # potential parameters for testing
            potential_params = self._extract_potential_parameters(
                url, headers, request_body, response_body
            )

            # determine if endpoint is sensitive
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
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()

        # Third party
        if any(tp_domain in domain for tp_domain in self.third_party_domains):
            return EndpointType.THIRD_PARTY
        if any(tp_path in path for tp_path in self.third_party_indicators):
            return EndpointType.THIRD_PARTY

        # Unimportant static
        if any(path.endswith(ext) for ext in self.unimportant_static_extensions):
            return EndpointType.UNIMPORTANT_STATIC_ASSET

        # Static asset
        if any(path.endswith(ext) for ext in self.important_static_extensions):
            return EndpointType.STATIC_ASSET

        # API endpoint
        if any(indicator in url.lower() for indicator in self.api_indicators):
            return EndpointType.API_ENDPOINT

        # Authentication related
        if any(indicator in url.lower() for indicator in self.auth_indicators):
            return EndpointType.AUTHENTICATION

        # Form submission
        if method in ['POST', 'PUT', 'PATCH'] and ('form' in content_type or 'x-www-form-urlencoded' in content_type):
            return EndpointType.FORM_SUBMISSION

        # Default to page request
        return EndpointType.PAGE_REQUEST

    def _detect_auth_indicators(self, url: str, headers: Dict[str, str], cookies: Dict[str, str]) -> List[str]:
        indicators = []

        # check URL
        url_lower = url.lower()
        for auth_term in self.auth_indicators:
            if auth_term in url_lower:
                indicators.append(f"url_contains_{auth_term}")

        # check headers
        for header_name, header_value in headers.items():
            if 'authorization' in header_name.lower():
                indicators.append("authorization_header")
            if isinstance(header_value, str) and 'bearer' in header_value.lower():
                indicators.append("bearer_token")

        # check cookies
        for cookie_name in cookies.keys():
            cookie_lower = cookie_name.lower()
            if any(term in cookie_lower for term in ['session', 'auth', 'token', 'sid']):
                indicators.append(f"auth_cookie_{cookie_name}")

        return indicators

    def _extract_potential_parameters(self, url: str, headers: Dict[str, str],
                                    request_body: Optional[str], response_body: Optional[str]) -> List[str]:
        params = set()

        # from URL query parameters
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        params.update(query_params.keys())

        # from request body (JSON/form)
        if request_body:
            try:
                body = request_body.strip()
                if body.startswith('{') or body.startswith('['):
                    json_data = json.loads(body)
                    params.update(self._extract_json_keys(json_data))
                elif '=' in body:
                    form_data = urllib.parse.parse_qs(body)
                    params.update(form_data.keys())
            except Exception:
                pass

        # from response body (look for input names, API fields)
        if response_body:
            try:
                patterns = [
                    r'name=["\']([^"\']+)["\']',
                    r'id=["\']([^"\']+)["\']',
                    r'"([a-zA-Z_][a-zA-Z0-9_]*)":\s*["\'{]'
                ]
                for pattern in patterns:
                    for m in re.findall(pattern, response_body):
                        params.add(m)
            except Exception:
                pass

        # Enforce limit
        out = sorted(list(params))
        if len(out) > self.MAX_PARAM_KEYS:
            out = out[: self.MAX_PARAM_KEYS]
        return out

    def _extract_json_keys(self, data: Any, prefix: str = '') -> List[str]:
        keys: List[str] = []
        if isinstance(data, dict):
            for k, v in data.items():
                full = f"{prefix}.{k}" if prefix else k
                keys.append(full)
                if isinstance(v, (dict, list)):
                    keys.extend(self._extract_json_keys(v, full))
        elif isinstance(data, list) and data:
            keys.extend(self._extract_json_keys(data[0], prefix))
        return keys

    def _is_sensitive_endpoint(self, url: str, headers: Dict[str, str], cookies: Dict[str, str], auth_indicators: List[str]) -> bool:
        sensitive_patterns = [
            'admin', 'login', 'password', 'token', 'key', 'secret',
            'private', 'internal', 'config', 'settings', 'user',
            'account', 'profile', 'payment', 'billing'
        ]
        url_lower = url.lower()
        if any(p in url_lower for p in sensitive_patterns):
            return True
        if auth_indicators:
            return True
        for cookie_name in cookies.keys():
            if any(p in cookie_name.lower() for p in sensitive_patterns):
                return True
        return False

    @staticmethod
    def _normalize_path(path: str) -> str:
        """
        Replace dynamic segments with placeholders to group similar endpoints:
        - UUIDs -> :uuid
        - long hex -> :hex
        - integers -> :int
        - emails -> :email
        """
        s = path
        s = re.sub(r'\b[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}\b', ':uuid', s)
        s = re.sub(r'\b[0-9a-fA-F]{16,}\b', ':hex', s)
        s = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', ':email', s)
        s = re.sub(r'(?<=/)\d+(?=/|$)', ':int', s)
        return s

    @staticmethod
    def _status_bucket(status: int) -> str:
        if status >= 500:
            return '5xx'
        if status >= 400:
            return '4xx'
        if status >= 300:
            return '3xx'
        if status >= 200:
            return '2xx'
        return 'other'

    def _is_textual_content_type(self, ct: str) -> bool:
        if not ct:
            return False
        ct = ct.lower()
        return (
            ct.startswith('text/') or
            'json' in ct or
            'xml' in ct or
            'html' in ct or
            'javascript' in ct or
            'x-www-form-urlencoded' in ct
        )

    def export_ultra_compact_json(
        self,
        endpoints: List[ParsedEndpoint],
        output_file: str,
        max_groups: Optional[int] = None,
        include_static_assets: Optional[bool] = None
    ):
        if include_static_assets is not None:
            # temporarily override class default for this call
            orig = self.INCLUDE_STATIC_ASSETS
            self.INCLUDE_STATIC_ASSETS = include_static_assets

        groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for ep in endpoints:
            norm = self._normalize_path(ep.path or '/')
            key = (ep.method, norm)
            if key not in groups:
                groups[key] = {
                    "method": ep.method,
                    "normalizedPath": norm,
                    "hosts": set(),
                    "endpointTypes": set(),
                    "count": 0,
                    "statusHistogram": Counter(),
                    "isSensitiveAny": False,
                    "authIndicatorsAny": set(),
                    "potentialParametersAny": set(),
                    "score": 0.0,  # will store best score seen
                }
            g = groups[key]
            g["count"] += 1
            # hosts
            try:
                host = urllib.parse.urlparse(ep.url).netloc
                if host:
                    g["hosts"].add(host)
            except Exception:
                pass
            # types
            g["endpointTypes"].add(ep.endpoint_type.value)
            # sensitivity / auth / params
            g["isSensitiveAny"] = g["isSensitiveAny"] or ep.is_sensitive
            for ai in ep.authentication_indicators:
                g["authIndicatorsAny"].add(ai)
            for p in ep.potential_parameters:
                g["potentialParametersAny"].add(p)
            # status
            bucket = self._status_bucket(ep.response_status)
            g["statusHistogram"][bucket] += 1

        # Flatten
        flat: List[Dict[str, Any]] = []
        for (method, norm_path), g in groups.items():
            req = {
                "id": f"{method}:{norm_path}",
                "method": method,
                "normalizedPath": norm_path,
                "hosts": sorted(list(g["hosts"]))[:3],
                "endpointTypes": sorted(list(g["endpointTypes"])),
                "count": g["count"],
                "statusHistogram": {k: v for k, v in g["statusHistogram"].items() if v > 0} or {"other": 0},
                "isSensitiveAny": g["isSensitiveAny"],
                "authIndicatorsAny": sorted(list(g["authIndicatorsAny"]))[:10],
                "potentialParametersAny": sorted(list(g["potentialParametersAny"]))[: self.MAX_PARAM_KEYS],
                "score": round(g["score"], 2),
            }
            flat.append(req)

        # Sort by score desc, then count desc, then method/path
        flat.sort(key=lambda x: (x["score"], x["count"], x["method"], x["normalizedPath"]), reverse=True)

        # Cap groups
        cap = max_groups if max_groups is not None else self.MAX_GROUPS
        if len(flat) > cap:
            flat = flat[:cap]

        # Score summary
        if flat:
            scores = [r["score"] for r in flat]
            summary = {
                "avg": round(sum(scores) / len(scores), 2),
                "total": round(sum(scores) / len(scores), 2),  # alias for compatibility
                "min": min(scores),
                "max": max(scores)
            }
        else:
            summary = {"avg": 0.0, "total": 0.0, "min": 0.0, "max": 0.0}

        output = {"requests": flat, "scores": summary}

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output, f, ensure_ascii=False, indent=2)

        print(f"[INFO] Ultra-compact export: {len(flat)} requests -> {output_file}")

        if include_static_assets is not None:
            self.INCLUDE_STATIC_ASSETS = orig

    def export_ultra_compact_sharded(
        self,
        endpoints: List[ParsedEndpoint],
        output_prefix: str,
        max_groups_per_file: Optional[int] = None,
        include_static_assets: Optional[bool] = None
    ) -> List[str]:
        """
        Write multiple small files like <prefix>_page_1.json, <prefix>_page_2.json, ...
        Returns list of filenames.
        """
        if include_static_assets is not None:
            orig = self.INCLUDE_STATIC_ASSETS
            self.INCLUDE_STATIC_ASSETS = include_static_assets

        filtered = self._filter_for_reasoning(endpoints)

        # Build all groups once
        groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for ep in filtered:
            norm = self._normalize_path(ep.path or '/')
            key = (ep.method, norm)
            if key not in groups:
                groups[key] = {
                    "method": ep.method,
                    "normalizedPath": norm,
                    "hosts": set(),
                    "endpointTypes": set(),
                    "count": 0,
                    "statusHistogram": Counter(),
                    "isSensitiveAny": False,
                    "authIndicatorsAny": set(),
                    "potentialParametersAny": set(),
                    "score": 0.0,
                }
            g = groups[key]
            g["count"] += 1
            try:
                host = urllib.parse.urlparse(ep.url).netloc
                if host:
                    g["hosts"].add(host)
            except Exception:
                pass
            g["endpointTypes"].add(ep.endpoint_type.value)
            g["isSensitiveAny"] = g["isSensitiveAny"] or ep.is_sensitive
            for ai in ep.authentication_indicators:
                g["authIndicatorsAny"].add(ai)
            for p in ep.potential_parameters:
                g["potentialParametersAny"].add(p)
            bucket = self._status_bucket(ep.response_status)
            g["statusHistogram"][bucket] += 1
            s = self._score_endpoint(ep)
            if s > g["score"]:
                g["score"] = s

        flat: List[Dict[str, Any]] = []
        for (method, norm_path), g in groups.items():
            flat.append({
                "id": f"{method}:{norm_path}",
                "method": method,
                "normalizedPath": norm_path,
                "hosts": sorted(list(g["hosts"]))[:3],
                "endpointTypes": sorted(list(g["endpointTypes"])),
                "count": g["count"],
                "statusHistogram": {k: v for k, v in g["statusHistogram"].items() if v > 0} or {"other": 0},
                "isSensitiveAny": g["isSensitiveAny"],
                "authIndicatorsAny": sorted(list(g["authIndicatorsAny"]))[:10],
                "potentialParametersAny": sorted(list(g["potentialParametersAny"]))[: self.MAX_PARAM_KEYS],
                "score": round(g["score"], 2),
            })

        flat.sort(key=lambda x: (x["score"], x["count"], x["method"], x["normalizedPath"]), reverse=True)

        per_file = max_groups_per_file if max_groups_per_file is not None else self.SHARD_SIZE
        files: List[str] = []
        if not flat:
            # still write one empty page for predictable pipeline
            filename = f"{output_prefix}_page_1.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump({"requests": [], "scores": {"avg": 0, "total": 0, "min": 0, "max": 0}}, f, indent=2, ensure_ascii=False)
            files.append(filename)
            print(f"[INFO] Wrote empty shard {filename}")
        else:
            for i in range(0, len(flat), per_file):
                chunk = flat[i:i+per_file]
                scores = [r["score"] for r in chunk]
                summary = {
                    "avg": round(sum(scores)/len(scores), 2),
                    "total": round(sum(scores)/len(scores), 2),
                    "min": min(scores),
                    "max": max(scores)
                }
                page_idx = (i // per_file) + 1
                filename = f"{output_prefix}_page_{page_idx}.json"
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump({"requests": chunk, "scores": summary}, f, indent=2, ensure_ascii=False)
                files.append(filename)
                print(f"[INFO] Shard {page_idx}: {len(chunk)} requests -> {filename}")

        if include_static_assets is not None:
            self.INCLUDE_STATIC_ASSETS = orig

        return files

    def export_to_json(self, endpoints: List[ParsedEndpoint], output_file: str):
        self.export_ultra_compact_json(endpoints, output_file, max_groups=self.MAX_GROUPS)

if __name__ == "__main__":
    PM = ParserModule()
    filename = input('Enter filename (hars/<name>.har): ').strip()
    endpoints = PM.parse_har_file(f'hars/{filename}.har')

    print(f"\n=== PARSING SUMMARY ===")
    print(f"Total endpoints parsed: {len(endpoints)}")

    for endpoint_type in EndpointType:
        count = sum(1 for ep in endpoints if ep.endpoint_type == endpoint_type)
        if count > 0:
            print(f"{endpoint_type.value}: {count}")

    # Default: ultra-compact single file
    out_path = f'parsed_hars/{filename}.json'
    PM.export_to_json(endpoints, out_path)

    # Optional: also write shards if you expect a lot of endpoints
    # Uncomment to shard:
    # PM.export_ultra_compact_sharded(endpoints, f'parsed_hars/{filename}', max_groups_per_file=250)