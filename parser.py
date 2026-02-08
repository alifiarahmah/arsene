"""
HAR Parser Module

This module parses raw HAR files using haralyzer library and filters them
according to security testing requirements. It creates filtered JSON outputs
with only relevant security-related information.

Filtering Rules:
1. Remove static assets (.css, .js, .png, .jpg, .gif, .svg, .woff, .ico)
2. Remove third-party requests (analytics, CDNs)
3. Keep only relevant headers (Content-Type, Authorization, Cookie, X-*)
4. Filter body content based on type (JSON, HTML, text, XML)
5. Preserve sensitive fields (id, user_id, role, price, amount, status, state, token, email)
6. Handle base64-encoded content from ZAP recordings
"""

import base64
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from haralyzer import HarParser


class HarFilter:
    """Filter HAR files based on security testing requirements."""

    # Static asset extensions to filter out
    STATIC_EXTENSIONS = {
        '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg',
        '.woff', '.woff2', '.ico', '.ttf', '.eot', '.webp', '.map'
    }

    # Third-party domains to filter out (common analytics and CDNs)
    THIRD_PARTY_DOMAINS = {
        'google-analytics.com', 'googletagmanager.com', 'googleadservices.com',
        'facebook.com', 'facebook.net', 'connect.facebook.net',
        'doubleclick.net', 'googlesyndication.com',
        'cloudflare.com', 'cloudflareinsights.com',
        'stats.g.doubleclick.net', 'bat.bing.com',
        'analytics.twitter.com', 'pixel.wp.com',
        'cdn.jsdelivr.net', 'cdnjs.cloudflare.com',
        'unpkg.com', 'cdnjs.cloudflare.com',
        'fonts.googleapis.com', 'fonts.gstatic.com',
        'maxcdn.bootstrapcdn.com', 'code.jquery.com'
    }

    # Relevant headers to keep
    RELEVANT_HEADERS_PREFIXES = (
        'content-type', 'authorization', 'cookie', 'set-cookie',
        'accept', 'x-', 'location', 'referer', 'origin'
    )

    # Sensitive field keywords (always preserve these)
    SENSITIVE_KEYWORDS = {
        'id', 'user_id', 'role', 'price', 'amount', 'status', 'state',
        'token', 'email', 'password', 'username', 'name', 'session',
        'auth', 'csrf', 'jwt', 'api_key', 'apikey', 'secret',
        'account', 'balance', 'credit', 'debit', 'transaction'
    }

    def __init__(self, har_file_path: str):
        """
        Initialize the HAR filter.

        Args:
            har_file_path: Path to the HAR file to parse
        """
        self.har_file_path = Path(har_file_path)
        self.filename = self.har_file_path.stem

        # Load HAR file using haralyzer
        with open(self.har_file_path, 'r', encoding='utf-8') as f:
            self.har_data = json.load(f)

        self.har_parser = HarParser(self.har_data)

    def _is_static_asset(self, url: str) -> bool:
        """Check if URL is a static asset."""
        parsed = urlparse(url)
        path = parsed.path.lower()
        return any(path.endswith(ext) for ext in self.STATIC_EXTENSIONS)

    def _is_third_party(self, url: str) -> bool:
        """Check if URL is from a third-party domain."""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        return any(third_party in domain for third_party in self.THIRD_PARTY_DOMAINS)

    def _should_filter_request(self, entry: Dict[str, Any]) -> bool:
        """
        Determine if a request should be filtered out.

        Args:
            entry: HAR entry object

        Returns:
            True if the request should be filtered out (excluded)
        """
        url = entry['request']['url']

        # Filter static assets
        if self._is_static_asset(url):
            return True

        # Filter third-party requests
        if self._is_third_party(url):
            return True

        return False

    def _is_relevant_header(self, header_name: str) -> bool:
        """
        Check if a header is relevant and should be kept.

        Args:
            header_name: Header name to check

        Returns:
            True if the header should be kept
        """
        header_lower = header_name.lower()

        # Keep specific headers or those starting with relevant prefixes
        return any(
            header_lower == prefix or header_lower.startswith(prefix)
            for prefix in self.RELEVANT_HEADERS_PREFIXES
        )

    def _has_sensitive_field(self, key: str) -> bool:
        """
        Check if a key contains sensitive keywords.

        Args:
            key: Field key to check

        Returns:
            True if the key contains sensitive keywords
        """
        key_lower = key.lower()
        return any(keyword in key_lower for keyword in self.SENSITIVE_KEYWORDS)

    def _decode_base64_content(self, text: str, encoding: Optional[str] = None) -> str:
        """
        Decode base64-encoded content from ZAP recordings.

        Args:
            text: The content text (may be base64 encoded)
            encoding: Encoding type from HAR (e.g., 'base64')

        Returns:
            Decoded content string
        """
        if encoding == 'base64' and text:
            try:
                decoded_bytes = base64.b64decode(text)
                # Try to decode as UTF-8, fallback with error handling
                return decoded_bytes.decode('utf-8', errors='replace')
            except Exception:
                # If decoding fails, return original
                return text
        return text

    def _filter_json_content(self, data: Any, depth: int = 0) -> Any:
        """
        Filter JSON content by truncating repetitive arrays.
        Preserves sensitive fields and state-changing values.

        Args:
            data: JSON data to filter
            depth: Current recursion depth

        Returns:
            Filtered JSON data
        """
        if depth > 50:  # Prevent infinite recursion
            return data

        if isinstance(data, dict):
            filtered = {}
            for key, value in data.items():
                # Always keep sensitive fields fully
                if self._has_sensitive_field(key):
                    filtered[key] = value
                else:
                    filtered[key] = self._filter_json_content(value, depth + 1)
            return filtered

        elif isinstance(data, list):
            # Keep only first 2 items for long repetitive arrays
            # unless they contain sensitive fields
            if len(data) > 2:
                # Check if items contain sensitive fields
                has_sensitive = False
                for item in data[:3]:
                    if isinstance(item, dict):
                        if any(self._has_sensitive_field(k) for k in item.keys()):
                            has_sensitive = True
                            break
                    elif isinstance(item, str):
                        if self._has_sensitive_field(item):
                            has_sensitive = True
                            break

                if has_sensitive:
                    return [self._filter_json_content(item, depth + 1) for item in data]
                else:
                    return [
                        self._filter_json_content(item, depth + 1) for item in data[:2]
                    ] + [{"_comment": f"... ({len(data) - 2} more items truncated)"}]
            return [self._filter_json_content(item, depth + 1) for item in data]

        return data

    def _filter_html_content(self, content: str) -> str:
        """
        Filter HTML content to keep only relevant business logic elements.

        Args:
            content: HTML content to filter

        Returns:
            Filtered HTML content
        """
        # Find relevant tags for business logic
        relevant_tags = ['form', 'input', 'a', 'button', 'select', 'textarea']
        filtered_elements = []

        for tag in relevant_tags:
            # Find all occurrences of the tag
            pattern = f'<{tag}[^>]*>'
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)

            for match in matches:
                tag_text = match.group(0)

                # Check if it contains sensitive attributes
                has_sensitive = any(
                    f'{keyword}=' in tag_text.lower()
                    for keyword in self.SENSITIVE_KEYWORDS
                )

                if has_sensitive:
                    filtered_elements.append(tag_text)
                else:
                    # Keep only specific attributes
                    relevant_attrs = [
                        'name', 'id', 'class', 'type', 'action', 'method',
                        'href', 'value', 'src', 'data-', 'for', 'placeholder'
                    ]

                    # Extract and keep only relevant attributes
                    all_attrs = re.finditer(r'([\w-]+)=["\'][^"\']*["\']', tag_text)
                    kept_attrs = []

                    for attr_match in all_attrs:
                        attr_name = attr_match.group(1)
                        if (attr_name.lower() in relevant_attrs or
                            attr_name.startswith('data-')):
                            kept_attrs.append(attr_match.group(0))

                    # Reconstruct tag with only relevant attributes
                    if kept_attrs:
                        tag_name = re.match(r'<(\w+)', tag_text)
                        if tag_name:
                            reconstructed = f'<{tag_name.group(1)} {" ".join(kept_attrs)}>'
                            filtered_elements.append(reconstructed)
                    else:
                        filtered_elements.append(tag_text)

        if filtered_elements:
            return '\n'.join(filtered_elements)

        # Fallback: return first 2000 characters
        return content[:2000]

    def _filter_text_content(self, content: str) -> str:
        """
        Filter text/xml content.

        Args:
            content: Text content to filter

        Returns:
            Filtered text content (first 2000 characters, more if sensitive)
        """
        # Check for sensitive fields before truncating
        content_lower = content.lower()
        if any(keyword in content_lower for keyword in self.SENSITIVE_KEYWORDS):
            # Return more content if sensitive fields are present
            return content[:5000]

        return content[:2000]

    def _filter_body_content(
        self,
        text: str,
        content_type: str,
        encoding: Optional[str] = None
    ) -> str:
        """
        Filter body content based on content-type and encoding.

        Args:
            text: Body content to filter
            content_type: Content-Type header value
            encoding: Encoding type (e.g., 'base64') from HAR

        Returns:
            Filtered body content
        """
        if not text:
            return text

        # Decode base64 if present
        decoded_text = self._decode_base64_content(text, encoding)

        if not content_type:
            return decoded_text[:2000]

        content_type_lower = content_type.lower()

        # JSON content
        if 'application/json' in content_type_lower:
            try:
                json_data = json.loads(decoded_text)
                filtered_data = self._filter_json_content(json_data)
                return json.dumps(filtered_data, indent=2, ensure_ascii=False)
            except json.JSONDecodeError:
                # If JSON parsing fails, return as-is with length limit
                return decoded_text[:2000]

        # HTML content
        elif 'text/html' in content_type_lower:
            return self._filter_html_content(decoded_text)

        # XML or plain text
        elif ('text/xml' in content_type_lower or
              'application/xml' in content_type_lower or
              'text/plain' in content_type_lower):
            return self._filter_text_content(decoded_text)

        # Default: return first 2000 characters
        return decoded_text[:2000]

    def _filter_headers(self, headers: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Filter headers to keep only relevant ones.

        Args:
            headers: List of header dictionaries

        Returns:
            Filtered list of headers
        """
        filtered = []
        for header in headers:
            if self._is_relevant_header(header['name']):
                filtered.append(header)
        return filtered

    def _filter_entry(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Filter a single HAR entry.

        Args:
            entry: HAR entry object

        Returns:
            Filtered entry or None if it should be excluded
        """
        # Check if request should be filtered
        if self._should_filter_request(entry):
            return None

        # Create filtered entry
        filtered_entry = {
            'startedDateTime': entry.get('startedDateTime'),
            'time': entry.get('time'),
            'request': {
                'method': entry['request']['method'],
                'url': entry['request']['url'],
                'httpVersion': entry['request'].get('httpVersion'),
                'headers': self._filter_headers(entry['request'].get('headers', [])),
                'queryString': entry['request'].get('queryString', []),
                'cookies': entry['request'].get('cookies', []),
            },
            'response': {
                'status': entry['response']['status'],
                'statusText': entry['response'].get('statusText'),
                'httpVersion': entry['response'].get('httpVersion'),
                'headers': self._filter_headers(entry['response'].get('headers', [])),
                'cookies': entry['response'].get('cookies', []),
                'content': {
                    'size': entry['response']['content'].get('size'),
                    'mimeType': entry['response']['content'].get('mimeType'),
                },
                'redirectURL': entry['response'].get('redirectURL', ''),
            },
            'cache': entry.get('cache', {}),
            'timings': entry.get('timings', {}),
        }

        # Add postData if present
        if 'postData' in entry['request'] and entry['request']['postData']:
            post_data = entry['request']['postData']
            filtered_entry['request']['postData'] = {
                'mimeType': post_data.get('mimeType', ''),
                'params': post_data.get('params', []),
            }

            # Filter post data text content with base64 handling
            if 'text' in post_data and post_data['text']:
                content_type = post_data.get('mimeType', 'application/octet-stream')
                # Check for encoding (ZAP uses base64)
                encoding = post_data.get('encoding')
                filtered_entry['request']['postData']['text'] = self._filter_body_content(
                    post_data['text'], content_type, encoding
                )

        # Add response content text if present with base64 handling
        response_content = entry['response']['content']
        if 'text' in response_content and response_content['text']:
            content_type = response_content.get('mimeType', 'application/octet-stream')
            # Check for encoding (ZAP uses base64)
            encoding = response_content.get('encoding')
            filtered_text = self._filter_body_content(
                response_content['text'], content_type, encoding
            )

            original_length = len(response_content['text'])
            if len(filtered_text) < original_length:
                filtered_entry['response']['content']['text'] = filtered_text
                filtered_entry['response']['content']['_truncated'] = True
                filtered_entry['response']['content']['_originalSize'] = original_length
            else:
                filtered_entry['response']['content']['text'] = filtered_text

        return filtered_entry

    def parse(self, output_dir: Optional[str] = None) -> str:
        """
        Parse the HAR file and create filtered JSON output.

        Args:
            output_dir: Output directory path (default: parsed_hars)

        Returns:
            Path to the output file
        """
        # Determine output directory
        if output_dir is None:
            output_path = self.har_file_path.parent.parent / 'parsed_hars'
        else:
            output_path = Path(output_dir)

        output_path.mkdir(parents=True, exist_ok=True)

        # Get all entries from HAR
        entries = self.har_data.get('log', {}).get('entries', [])

        # Filter entries
        filtered_entries = []
        for entry in entries:
            filtered_entry = self._filter_entry(entry)
            if filtered_entry:
                filtered_entries.append(filtered_entry)

        # Create output with only entries array
        output_data = filtered_entries

        # Write output file
        output_file_path = output_path / f'{self.filename}.json'
        with open(output_file_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)

        return str(output_file_path)

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the HAR file.

        Returns:
            Dictionary containing statistics
        """
        entries = self.har_data.get('log', {}).get('entries', [])

        stats: Dict[str, Any] = {
            'totalEntries': len(entries),
            'staticAssets': 0,
            'thirdPartyRequests': 0,
            'relevantRequests': 0,
            'domains': set(),
            'methods': {},
            'statusCodes': {},
            'mimeTypeCounts': {},
            'base64EncodedCount': 0,
        }

        for entry in entries:
            url = entry['request']['url']

            if self._is_static_asset(url):
                stats['staticAssets'] += 1
            elif self._is_third_party(url):
                stats['thirdPartyRequests'] += 1
            else:
                stats['relevantRequests'] += 1

            # Track domains
            parsed = urlparse(url)
            stats['domains'].add(parsed.netloc)

            # Track methods
            method = entry['request']['method']
            stats['methods'][method] = stats['methods'].get(method, 0) + 1

            # Track status codes
            status = entry['response']['status']
            stats['statusCodes'][status] = stats['statusCodes'].get(status, 0) + 1

            # Track MIME types
            mime_type = entry['response']['content'].get('mimeType', 'unknown')
            stats['mimeTypeCounts'][mime_type] = stats['mimeTypeCounts'].get(mime_type, 0) + 1

            # Count base64 encoded responses
            if entry['response']['content'].get('encoding') == 'base64':
                stats['base64EncodedCount'] += 1

        stats['domains'] = sorted(list(stats['domains']))
        return stats


def parse_har_file(har_path: str, output_dir: Optional[str] = None) -> str:
    """
    Convenience function to parse a HAR file.

    Args:
        har_path: Path to the HAR file
        output_dir: Output directory path

    Returns:
        Path to the output file
    """
    har_filter = HarFilter(har_path)
    return har_filter.parse(output_dir)


def parse_all_hars_in_directory(
    directory: str,
    output_dir: Optional[str] = None
) -> List[str]:
    """
    Parse all HAR files in a directory.

    Args:
        directory: Directory containing HAR files
        output_dir: Output directory path

    Returns:
        List of output file paths
    """
    directory_path = Path(directory)
    output_paths = []

    for har_file in directory_path.glob('*.har'):
        try:
            output_path = parse_har_file(str(har_file), output_dir)
            output_paths.append(output_path)
            print(f'[OK] Parsed: {har_file.name} -> {output_path}')
        except Exception as e:
            print(f'[ERROR] Error parsing {har_file.name}: {e}')

    return output_paths


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print('Usage: python parser.py <har_file_or_directory> [output_dir]')
        print('\nExamples:')
        print('  python parser.py hars/ginandjuice-shop.har')
        print('  python parser.py hars/ parsed_hars/')
        sys.exit(1)

    input_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None

    input_file = Path(input_path)
    if input_file.is_file():
        result = parse_har_file(input_path, output_dir)
        print(f'Output: {result}')

        # Print statistics
        har_filter = HarFilter(input_path)
        stats = har_filter.get_statistics()
        print(f'\nStatistics:')
        print(f"  Total entries: {stats['totalEntries']}")
        print(f"  Static assets: {stats['staticAssets']}")
        print(f"  Third-party requests: {stats['thirdPartyRequests']}")
        print(f"  Relevant requests: {stats['relevantRequests']}")
        print(f"  Base64 encoded responses: {stats['base64EncodedCount']}")
        print(f"  Unique domains: {len(stats['domains'])}")

    elif input_file.is_dir():
        results = parse_all_hars_in_directory(input_path, output_dir)
        print(f'\nProcessed {len(results)} files')
    else:
        print(f'Error: {input_path} is not a valid file or directory')
        sys.exit(1)
