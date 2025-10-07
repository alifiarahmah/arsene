import json
import urllib.parse
import re
import os
import base64
from typing import Counter, Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import argparse

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
    potential_parameters: List[Dict[str, str]]
    response_body_truncated: bool = False  # NEW: track truncation
    response_encoding: Optional[str] = None  # NEW: track encoding

class ParserModule:
    MAX_PARAM_KEYS = 20
    RESPONSE_BODY_SNIFF_LIMIT = 1200
    STATIC_FILE_SIZE_LIMIT = 5 * 1024 * 1024  # NEW: 5MB limit for static files
    MAX_GROUPS = 250
    SHARD_SIZE = 250
    INCLUDE_STATIC_ASSETS = False
    HEADER_LENGTH_THRESHOLD = 50
    COMMON_LONG_HEADERS = {
        'authorization', 'cookie', 'set-cookie', 'user-agent',
        'accept', 'accept-encoding', 'accept-language', 'referer'
    }

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
            '.js', '.js.map', '.json', '.wasm', '.html', '.htm'
        }

        # NEW: Categorize static files for analysis
        self.analyzable_static_extensions = {
            '.js', '.html', '.htm'  # Primary targets for static analysis
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

    def _decode_response_body(self, content: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], bool]:
        """
        Decode response body from HAR content object.
        Returns: (decoded_text, encoding, was_truncated)
        """
        if 'text' not in content:
            return None, None, False

        text = content['text']
        encoding = content.get('encoding', None)
        size = content.get('size', 0)

        if not text:
            return None, encoding, False

        # Decode base64 if needed
        if encoding == 'base64':
            try:
                decoded_bytes = base64.b64decode(text)
                text = decoded_bytes.decode('utf-8', errors='ignore')
            except Exception as e:
                print(f"[WARN] Failed to decode base64 content: {e}")
                return None, encoding, False

        return text, encoding, False

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

            # NEW: Decode response body properly
            response_body = None
            response_encoding = None
            response_truncated = False

            if 'content' in response:
                content_obj = response['content']
                decoded_text, encoding, _ = self._decode_response_body(content_obj)
                response_encoding = encoding

                if decoded_text:
                    # Check if this is a static file we want to keep in full
                    is_analyzable_static = any(
                        url.lower().endswith(ext) for ext in self.analyzable_static_extensions
                    )

                    if is_analyzable_static:
                        # Keep full content but enforce size limit
                        if len(decoded_text) > self.STATIC_FILE_SIZE_LIMIT:
                            response_body = decoded_text[:self.STATIC_FILE_SIZE_LIMIT]
                            response_truncated = True
                        else:
                            response_body = decoded_text
                    else:
                        # For non-static, truncate for sniffing
                        if len(decoded_text) > self.RESPONSE_BODY_SNIFF_LIMIT:
                            response_body = decoded_text[:self.RESPONSE_BODY_SNIFF_LIMIT]
                            response_truncated = True
                        else:
                            response_body = decoded_text

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
                potential_parameters=potential_params,
                response_body_truncated=response_truncated,
                response_encoding=response_encoding
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
                                    request_body: Optional[str], response_body: Optional[str]) -> List[Dict[str, str]]:
        params = {}

        def guess_type(value: Any) -> str:
            if isinstance(value, bool):
                return "boolean"
            if isinstance(value, int):
                return "integer"
            if isinstance(value, float):
                return "float"
            if isinstance(value, str):
                v = value.strip()
                if v.isdigit():
                    return "integer"
                try:
                    float(v)
                    return "float"
                except:
                    if v.lower() in ["true", "false"]:
                        return "boolean"
                return "string"
            return "string"

        # from URL query parameters
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        for k, v in query_params.items():
            sample = v[0] if v else ""
            params[k] = guess_type(sample)

        # from request body (JSON/form)
        if request_body:
            try:
                body = request_body.strip()
                if body.startswith('{') or body.startswith('['):
                    json_data = json.loads(body)
                    def walk_json(obj, prefix=""):
                        if isinstance(obj, dict):
                            for kk, vv in obj.items():
                                name = f"{prefix}.{kk}" if prefix else kk
                                params[name] = guess_type(vv)
                                if isinstance(vv, (dict, list)):
                                    walk_json(vv, name)
                        elif isinstance(obj, list) and obj:
                            walk_json(obj[0], prefix)
                    walk_json(json_data)
                elif '=' in body:
                    form_data = urllib.parse.parse_qs(body)
                    for k, v in form_data.items():
                        sample = v[0] if v else ""
                        params[k] = guess_type(sample)
            except Exception:
                pass

        # from response body (look for input names, API fields)
        if response_body:
            try:
                patterns = [
                    r'name=["\']([^"\']+)["\']',
                    r'id=["\']([^"\']+)["\']',
                    r'"([a-zA-Z_][a-zA-Z0-9_]*)":\s*"?([^,"}]+)"?'
                ]
                for pattern in patterns:
                    matches = re.findall(pattern, response_body)
                    if pattern == r'"([a-zA-Z_][a-zA-Z0-9_]*)":\s*"?([^,"}]+)"?':
                        for k, v in matches:
                            params[k] = guess_type(v)
                    else:
                        for m in matches:
                            params[m] = "string"
            except Exception:
                pass

        # Enforce limit and convert to list of dicts
        out = [{"name": k, "type": t} for k, t in params.items()]
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

    def _should_separate_header(self, header_name: str, header_value: str) -> bool:
        """Determine if a header should be separated based on length or common patterns"""
        header_name_lower = header_name.lower()

        # Always separate common long headers
        if header_name_lower in self.COMMON_LONG_HEADERS:
            return True

        # Separate if value exceeds threshold
        if len(header_value) > self.HEADER_LENGTH_THRESHOLD:
            return True

        return False

    def _extract_separated_headers(self, all_headers: Dict[str, set]) -> Tuple[Dict[str, str], Dict[str, Any]]:
        """
        Extract headers that should be separated and create references
        Returns: (separated_headers_dict, processed_headers_for_endpoints)
        """
        separated_headers = {}
        processed_headers = {}
        header_id_counter = 1

        for header_name, values_set in all_headers.items():
            values_list = sorted(list(values_set))

            # Check if any value in this header should be separated
            should_separate = any(
                self._should_separate_header(header_name, value)
                for value in values_list
            )

            if should_separate:
                if len(values_list) == 1:
                    header_id = f"h{header_id_counter}"
                    separated_headers[header_id] = {
                        "name": header_name,
                        "value": values_list[0]
                    }
                    processed_headers[header_name] = f"@{header_id}"
                    header_id_counter += 1
                else:
                    references = []
                    for value in values_list:
                        header_id = f"h{header_id_counter}"
                        separated_headers[header_id] = {
                            "name": header_name,
                            "value": value
                        }
                        references.append(f"@{header_id}")
                        header_id_counter += 1
                    processed_headers[header_name] = references
            else:
                processed_headers[header_name] = values_list[0] if len(values_list) == 1 else values_list

        return separated_headers, processed_headers

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

    def _save_static_assets(self, static_endpoints: List[ParsedEndpoint], assets_dir: str):
        """Save static assets to files replicating the directory structure from endpoint paths"""
        if not static_endpoints:
            print("[DEBUG] No static endpoints to save")
            return

        # Create base assets directory if it doesn't exist
        os.makedirs(assets_dir, exist_ok=True)
        print(f"[DEBUG] Created assets directory: {assets_dir}")

        saved_count = 0
        for ep in static_endpoints:
            if not ep.response_body:
                print(f"[DEBUG] Skipping {ep.url} - no response body")
                continue

            try:
                # Parse URL to get path structure
                parsed_url = urllib.parse.urlparse(ep.url)
                url_path = parsed_url.path.strip('/')

                if not url_path:
                    # Handle root path case
                    filename = f"index_{hash(ep.url) % 10000}"
                    # Add appropriate extension based on content type
                    if 'javascript' in ep.content_type or ep.content_type == 'application/javascript':
                        filename += '.js'
                    elif 'html' in ep.content_type:
                        filename += '.html'
                    elif 'json' in ep.content_type:
                        filename += '.json'
                    file_path = os.path.join(assets_dir, filename)
                else:
                    # Split path into directory parts and filename
                    path_parts = url_path.split('/')

                    if len(path_parts) == 1:
                        # File is at root level
                        filename = path_parts[0]
                        directory_path = assets_dir
                    else:
                        # File is in subdirectories
                        directory_parts = path_parts[:-1]
                        filename = path_parts[-1]

                        # Sanitize directory names for filesystem
                        sanitized_dirs = []
                        for dir_part in directory_parts:
                            sanitized_dir = re.sub(r'[<>:"/\\|?*]', '_', dir_part)
                            if sanitized_dir:  # Skip empty parts
                                sanitized_dirs.append(sanitized_dir)

                        # Create full directory path
                        directory_path = os.path.join(assets_dir, *sanitized_dirs)
                        os.makedirs(directory_path, exist_ok=True)

                    # Handle case where filename is empty (directory-only path)
                    if not filename:
                        filename = f"index_{hash(ep.url) % 10000}"
                        # Add appropriate extension based on content type
                        if 'javascript' in ep.content_type or ep.content_type == 'application/javascript':
                            filename += '.js'
                        elif 'html' in ep.content_type:
                            filename += '.html'
                        elif 'json' in ep.content_type:
                            filename += '.json'

                    # Sanitize filename for filesystem
                    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)

                    # Build full file path
                    file_path = os.path.join(directory_path, filename)

                # Handle duplicate filenames by appending counter
                counter = 1
                original_file_path = file_path
                original_filename = filename
                while os.path.exists(file_path):
                    name, ext = os.path.splitext(original_filename)
                    new_filename = f"{name}_{counter}{ext}"
                    file_path = os.path.join(os.path.dirname(original_file_path), new_filename)
                    counter += 1

                # Write file
                with open(file_path, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(ep.response_body)

                saved_count += 1

                # Log the relative path for debugging
                relative_path = os.path.relpath(file_path, assets_dir)
                print(f"[DEBUG] Saved: {ep.url} -> {relative_path}")

            except Exception as e:
                print(f"[ERROR] Failed to save static asset {ep.url}: {e}")
                continue

        print(f"[INFO] Saved {saved_count} static assets to {assets_dir} with directory structure preserved")

    # NEW: Export static files for LLM analysis
    def export_static_files_for_analysis(self, endpoints: List[ParsedEndpoint], output_file: str):
        """
        Export static files (.js, .html) with metadata for LLM analysis.
        Output format matches STEP S1 input schema.
        """
        static_files = []
        truncated_sources = []

        for ep in endpoints:
            # Only process analyzable static files
            if ep.endpoint_type != EndpointType.STATIC_ASSET:
                continue

            is_analyzable = any(
                ep.url.lower().endswith(ext) for ext in self.analyzable_static_extensions
            )

            if not is_analyzable:
                continue

            file_info = {
                "url": ep.url,
                "file_name": os.path.basename(urllib.parse.urlparse(ep.url).path),
                "content_type": ep.content_type,
                "size_bytes": len(ep.response_body) if ep.response_body else 0,
                "encoding": ep.response_encoding,
                "from_har": True,
                "text": ep.response_body,
                "truncated": ep.response_body_truncated,
                "response_headers": ep.response_headers,
                "referrer": ep.headers.get('referer', None)
            }

            static_files.append(file_info)

            if ep.response_body_truncated:
                truncated_sources.append(ep.url)

        output = {
            "file_index": [
                {
                    "url": f["url"],
                    "file_name": f["file_name"],
                    "content_type": f["content_type"],
                    "size_bytes": f["size_bytes"],
                    "truncated": f["truncated"]
                }
                for f in static_files
            ],
            "files": static_files,
            "needs_observation": len(truncated_sources) > 0,
            "truncated_sources": truncated_sources
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output, f, ensure_ascii=False, indent=2)

        print(f"[INFO] Exported {len(static_files)} static files for analysis -> {output_file}")
        if truncated_sources:
            print(f"[WARN] {len(truncated_sources)} files were truncated")

    def export_ultra_compact_json(
        self,
        endpoints: List[ParsedEndpoint],
        output_file: str,
        max_groups: Optional[int] = None,
        include_static_assets: Optional[bool] = None,
        assets_dir: Optional[str] = None
    ):
        if include_static_assets is not None:
            # temporarily override class default for this call
            orig = self.INCLUDE_STATIC_ASSETS
            self.INCLUDE_STATIC_ASSETS = include_static_assets

        # Filter out static assets before processing
        filtered_endpoints = []
        static_endpoints = []
        for ep in endpoints:
            if ep.endpoint_type in [EndpointType.STATIC_ASSET]:
                static_endpoints.append(ep)
            if ep.endpoint_type in [EndpointType.UNIMPORTANT_STATIC_ASSET]:
                continue
            filtered_endpoints.append(ep)

        print(f"[DEBUG] Found {len(static_endpoints)} static assets to save")

        # Group by exact path (no normalization)
        groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
        all_headers_collection: Dict[str, set] = {}  # Collect all headers across all endpoints

        for ep in filtered_endpoints:
            key = (ep.method, ep.path or '/')
            if key not in groups:
                groups[key] = {
                    "method": ep.method,
                    "path": ep.path or '/',
                    "hosts": set(),
                    "endpointTypes": set(),
                    "count": 0,
                    "statusHistogram": Counter(),
                    "isSensitiveAny": False,
                    "authIndicatorsAny": set(),
                    "parameters": set(),
                    "headers": {},
                }
            g = groups[key]
            g["count"] += 1

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
                g["parameters"].add((p["name"], p["type"]))

            # headers - collect all header keys and their values
            for header_name, header_value in ep.headers.items():
                if header_name not in g["headers"]:
                    g["headers"][header_name] = set()
                g["headers"][header_name].add(header_value)

                # Also collect globally for separation analysis
                if header_name not in all_headers_collection:
                    all_headers_collection[header_name] = set()
                all_headers_collection[header_name].add(header_value)

            # status
            bucket = self._status_bucket(ep.response_status)
            g["statusHistogram"][bucket] += 1

        # Extract separated headers (global dictionary)
        separated_headers, _ = self._extract_separated_headers(all_headers_collection)

        # Flatten
        flat: List[Dict[str, Any]] = []
        for (method, path), g in groups.items():
            # Apply header separation for each endpoint group
            _, headers_processed = self._extract_separated_headers(g["headers"])

            req = {
                "id": f"{method}:{path}",
                "method": method,
                "path": path,
                "hosts": sorted(list(g["hosts"]))[:3],
                "endpointTypes": sorted(list(g["endpointTypes"])),
                "count": g["count"],
                "statusHistogram": {k: v for k, v in g["statusHistogram"].items() if v > 0} or {"other": 0},
                "isSensitiveAny": g["isSensitiveAny"],
                "authIndicatorsAny": sorted(list(g["authIndicatorsAny"]))[:10],
                "parameters": sorted(list(g["parameters"]))[: self.MAX_PARAM_KEYS],
                "headers": headers_processed,
            }
            flat.append(req)

        # Sort by count desc, then method/path
        flat.sort(key=lambda x: (x["count"], x["method"], x["path"]), reverse=True)

        # Cap groups
        cap = max_groups if max_groups is not None else self.MAX_GROUPS
        if len(flat) > cap:
            flat = flat[:cap]

        # Build final output including separated headers
        output = {
            "separatedHeaders": separated_headers,
            "requests": flat
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output, f, ensure_ascii=False, indent=2)

        print(f"[INFO] Ultra-compact export: {len(flat)} requests, {len(separated_headers)} separated headers -> {output_file}")

        # Save static assets to directory if assets_dir is provided
        if assets_dir and static_endpoints:
            self._save_static_assets(static_endpoints, assets_dir)

        if include_static_assets is not None:
            self.INCLUDE_STATIC_ASSETS = orig

    def _filter_for_reasoning(self, endpoints: List[ParsedEndpoint]) -> List[ParsedEndpoint]:
        """Filter endpoints that are relevant for security testing"""
        filtered = []
        for ep in endpoints:
            # Skip both types of static assets unless explicitly included
            if not self.INCLUDE_STATIC_ASSETS and ep.endpoint_type in [EndpointType.UNIMPORTANT_STATIC_ASSET, EndpointType.STATIC_ASSET]:
                continue
            # Skip third party
            if ep.endpoint_type == EndpointType.THIRD_PARTY:
                continue
            filtered.append(ep)
        return filtered

    def export_to_json(self, endpoints: List[ParsedEndpoint], output_file: str, assets_dir: Optional[str] = None):
        self.export_ultra_compact_json(endpoints, output_file, max_groups=self.MAX_GROUPS, include_static_assets=False, assets_dir=assets_dir)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Parse HAR files and extract endpoints')
    parser.add_argument('filename', help='Filename without .har extension (e.g., "example" for hars/example.har)')
    args = parser.parse_args()
    filename = args.filename

    PM = ParserModule()
    endpoints = PM.parse_har_file(f'hars/{filename}.har')

    print(f"\n=== PARSING SUMMARY ===")
    print(f"Total endpoints parsed: {len(endpoints)}")

    for endpoint_type in EndpointType:
        count = sum(1 for ep in endpoints if ep.endpoint_type == endpoint_type)
        if count > 0:
            print(f"{endpoint_type.value}: {count}")

    # Create assets directory path based on filename
    assets_dir = f'parsed_hars/{filename}'

    # Default: ultra-compact single file for API endpoints
    out_path = f'parsed_hars/{filename}.json'
    PM.export_to_json(endpoints, out_path, assets_dir=assets_dir)

    # NEW: Export static files for LLM analysis
    static_out_path = f'parsed_hars/{filename}_static.json'
    PM.export_static_files_for_analysis(endpoints, static_out_path)