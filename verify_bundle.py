"""Verify approved ZIP bytes and every allowlisted entry before writing any site file."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import re
import urllib.request
import sys
from datetime import date
import struct
import zlib
from html.parser import HTMLParser
from zipfile import ZipFile


MARKET_SCHEMA = 'market-briefing-v1'
ROBOTS = b'User-agent: *\nDisallow: /\n'


def valid_market_id(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}-(AM|PM)(?:-SPECIAL)?', value):
        return False
    try:
        date.fromisoformat(value[:10])
    except ValueError:
        return False
    return True


def market_order(issue):
    # 같은 slot에서는 정기판 다음 특별판, PM은 모든 AM보다 뒤다.
    return (issue[:10], issue[11:13] == 'PM', issue.endswith('-SPECIAL'))


def market_entry_files(entry):
    """Presentation is part of an immutable entry, never inferred from files."""
    if 'presentation' in entry:
        if entry['presentation'] != 'html-v1':
            raise ValueError('Unknown market presentation')
        return ('index.html', 'style.css')
    return ('index.html', 'style.css') + tuple(f'{n:02}.png' for n in range(1, 7))


def validate_market(approved):
    prefix = approved['path_prefix']
    if not isinstance(prefix, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}/', prefix):
        raise ValueError('Invalid caller path token')
    policy = approved['retention']
    if set(policy) != {'editions'} or type(policy['editions']) is not int or not 1 <= policy['editions'] <= 1000:
        raise ValueError('Invalid retention policy')
    expected = {'index.html', '404.html', 'robots.txt', prefix+'index.html',
                prefix+'latest/index.html', prefix+'archive/index.html'}
    entries = approved['entries']
    if not entries or len({e['issue_id'] for e in entries.values()}) > policy['editions']:
        raise ValueError('Invalid retained editions')
    for key, entry in entries.items():
        if set(entry) not in ({'issue_id', 'revision', 'path', 'build_id'},
                              {'issue_id', 'revision', 'path', 'build_id', 'presentation'}):
            raise ValueError('Forbidden public entry field')
        issue, revision = entry['issue_id'], entry['revision']
        if not valid_market_id(issue) or type(revision) is not int or revision < 1:
            raise ValueError('Invalid market edition/revision')
        suffix = '' if revision == 1 else f'/revisions/r{revision}'
        if key != issue + ('' if revision == 1 else f'-r{revision}') or entry['path'] != prefix+issue+suffix:
            raise ValueError('Edition/path mismatch')
        if not isinstance(entry['build_id'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', entry['build_id']):
            raise ValueError('Invalid market build ID')
        expected.update(entry['path']+'/'+name for name in market_entry_files(entry))
    if expected != set(approved['files']):
        raise ValueError('Files do not match market contract')
    allowed = {'schema_version', 'path_prefix', 'retention', 'entries', 'files',
               'site_hash', 'archive', 'release_tag', 'asset'}
    if set(approved) - allowed:
        raise ValueError('Forbidden public manifest field')


class HTMLMetadata(HTMLParser):
    """Only active, explicit document-head metadata counts (never template data)."""
    def __init__(self):
        super().__init__()
        self.meta = {}
        self.links = []
        self.in_head = False
        self.head_seen = False
        self.head_closed = False
        self.inert = []
        self.raw_text = None
    def handle_startendtag(self, tag, attrs):
        # HTML's trailing slash does not close non-void elements. Reject it
        # rather than let HTMLParser synthesize an end tag and activate metadata.
        void = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
                'link', 'meta', 'param', 'source', 'track', 'wbr'}
        if tag not in void:
            raise ValueError('Self-closing syntax on non-void HTML element')
        self.handle_starttag(tag, attrs)

    def handle_starttag(self, tag, attrs):
        if self.raw_text is not None:
            return
        if tag in ('template', 'noscript'):
            self.inert.append(tag)
            return
        if self.inert:
            return
        if tag == 'head':
            if not self.head_seen and not self.head_closed:
                self.in_head = self.head_seen = True
            return
        if tag == 'body' or (self.in_head and tag not in ('html', 'base', 'link', 'meta', 'title', 'style', 'script')):
            self.in_head = False
            self.head_closed = True
        if tag in ('title', 'textarea', 'iframe', 'xmp', 'noembed', 'noframes', 'plaintext'):
            self.raw_text = tag
            return
        if tag == 'meta' and self.in_head and len({k for k, _ in attrs}) != len(attrs):
            raise ValueError('Duplicate active meta attribute')
        attrs = dict(attrs)
        if tag == 'meta' and self.in_head:
            name = attrs.get('name', '').lower()
            if name in ('robots', 'market-build-id'):
                if name in self.meta:
                    raise ValueError('Duplicate active document metadata')
                self.meta[name] = attrs.get('content', '')
        if tag == 'a':
            self.links.append(attrs.get('href', ''))
    def handle_endtag(self, tag):
        if self.raw_text is not None:
            if tag == self.raw_text and tag != 'plaintext':
                self.raw_text = None
            return
        if self.inert:
            if tag == self.inert[-1]:
                self.inert.pop()
            return
        if tag == 'head':
            self.in_head = False
            self.head_closed = True


HTML_CSP = "default-src 'none'; style-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'"
HTML_SPACE = ' \t\n\r\f'

HTML_VOID = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
             'link', 'meta', 'param', 'source', 'track', 'wbr'}
SVG_TAGS = {'svg', 'g', 'path', 'polyline', 'line', 'rect', 'text', 'title', 'desc'}
NUMBER = r'[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?'
PUBLIC_ID = r'[A-Za-z][A-Za-z0-9_.-]{0,127}'


def literal_head_markup(raw):
    return raw.isascii() and '&' not in raw and not any(
        (ord(c) < 32 and c not in HTML_SPACE) or ord(c) == 127 for c in raw)


def numeric_geometry(value, count=None):
    import math
    if not isinstance(value, str) or not re.fullmatch(NUMBER+r'(?:[\s,]+'+NUMBER+r')*', value.strip()):
        raise ValueError('SVG geometry requires numeric values')
    numbers = [float(v) for v in re.findall(NUMBER, value)]
    if not all(math.isfinite(v) for v in numbers) or (count is not None and len(numbers) != count):
        raise ValueError('Invalid SVG geometry')
    return numbers


def validate_css(data):
    text = data.decode('utf-8')
    # A fixed renderer does not need CSS escapes. Reject rather than normalize
    # escape-obfuscated keywords, and remove comments before keyword checks.
    if '\\' in text or any(ord(c) < 32 and c not in '\t\n\r\f' for c in text):
        raise ValueError('CSS escapes/control characters not allowed')
    tokens = []
    offset = 0
    while offset < len(text):
        char = text[offset]
        if char in ('"', "'"):
            # Preserve the complete string. A comment delimiter inside it is
            # ordinary data and must never hide declarations between strings.
            end = offset + 1
            while end < len(text) and text[end] != char:
                if text[end] in '\n\r\f':
                    raise ValueError('Unterminated CSS string')
                end += 1
            if end == len(text):
                raise ValueError('Unterminated CSS string')
            tokens.append(text[offset:end+1])
            offset = end + 1
        elif text.startswith('/*', offset):
            end = text.find('*/', offset+2)
            if end < 0:
                raise ValueError('Invalid CSS comment')
            # Concatenation is conservative for comment-split resource tokens.
            offset = end + 2
        else:
            if text.startswith('*/', offset):
                raise ValueError('Invalid CSS comment')
            tokens.append(char)
            offset += 1
    clean = ''.join(tokens)
    if re.search(r'@\s*(?:import|font-face)\b|(?<![A-Za-z0-9_-])(?:url|expression|image-set|-webkit-image-set|image|cross-fade|paint|element)\s*\(|(?:https?|data|file|ftp|blob|javascript):|//', clean, re.I):
        raise ValueError('CSS external resources/fonts not allowed')


class HTMLPresentation(HTMLParser):
    """Strict static HTML plus a closed inline-SVG namespace, no XML expansion.

    Explicit end tags are required for non-void HTML and every SVG element.
    SVG title/desc are text-only; they cannot become HTML integration points.
    """
    # stdlib RCDATA is namespace-blind: SVG title is an integration point,
    # unlike HTML title. Expose tokens and enforce text-only titles ourselves.
    RCDATA_CONTENT_ELEMENTS = ()
    HTML_TAGS = {
        'html', 'head', 'body', 'meta', 'link', 'title', 'header', 'footer', 'main',
        'nav', 'section', 'article', 'aside', 'div', 'span', 'p', 'h1', 'h2', 'h3',
        'h4', 'h5', 'h6', 'a', 'ul', 'ol', 'li', 'dl', 'dt', 'dd', 'strong', 'em',
        'b', 'i', 'small', 'code', 'pre', 'blockquote', 'cite', 'time', 'abbr',
        'figure', 'figcaption', 'details', 'summary', 'table', 'caption', 'colgroup',
        'col', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td', 'br', 'hr', 'sup', 'sub',
    }
    HEAD_SHAPE = (
        ('meta', {'charset': 'utf-8'}),
        ('meta', {'name': 'viewport', 'content': 'width=device-width,initial-scale=1'}),
        ('meta', {'name': 'robots', 'content': 'noindex,nofollow'}),
        ('meta', {'name': 'referrer', 'content': 'no-referrer'}),
        ('meta', {'name': 'market-build-id', 'content': None}),
        ('meta', {'http-equiv': 'Content-Security-Policy', 'content': HTML_CSP}),
        ('title', {}),
        ('link', {'rel': 'stylesheet', 'href': 'style.css'}),
    )
    COMMON = {'id', 'class', 'title', 'lang', 'dir', 'role', 'aria-label',
              'aria-labelledby', 'aria-describedby', 'aria-hidden', 'tabindex', 'hidden'}
    SVG_COMMON = {'id', 'class', 'role', 'aria-label', 'aria-labelledby',
                  'aria-describedby', 'aria-hidden', 'transform'}
    SVG_GEOMETRY = {
        'svg': {'viewbox', 'width', 'height'}, 'g': set(),
        'path': {'d', 'pathlength'}, 'polyline': {'points', 'pathlength'},
        'line': {'x1', 'y1', 'x2', 'y2'},
        'rect': {'x', 'y', 'width', 'height', 'rx', 'ry'},
        'text': {'x', 'y', 'dx', 'dy', 'textlength'}, 'title': set(), 'desc': set(),
    }

    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.stack = []
        self.svg_stack = []
        self.svg_ids = set()
        self.svg_refs = set()
        self.ids = set()
        self.csp = False
        self.heads = 0
        self.head_index = 0
        self.head_complete = False
        self.html_seen = False
        self.body_seen = False
        self.doctype_seen = False

    def handle_startendtag(self, tag, attrs):
        if self.svg_stack or tag not in HTML_VOID:
            raise ValueError('Explicit non-void/SVG end tags required')
        self.handle_starttag(tag, attrs)

    def _attributes(self, attrs, svg=False):
        if len({k for k, _ in attrs}) != len(attrs):
            raise ValueError('Duplicate public HTML/SVG attribute')
        result = dict(attrs)
        for key, value in result.items():
            if key.startswith('on') or ':' in key or key == 'style':
                raise ValueError('Active/inline/namespace attribute not allowed')
            if value is None and key not in ('hidden', 'open'):
                raise ValueError('Attribute value required')
            if value is not None and any(ord(c) < 32 and c not in '\t\n\r' for c in value):
                raise ValueError('Invalid attribute control character')
        if 'id' in result:
            if not re.fullmatch(PUBLIC_ID, result['id']) or result['id'] in self.ids:
                raise ValueError('Invalid/duplicate public ID')
            self.ids.add(result['id'])
            if svg:
                self.svg_ids.add(result['id'])
        if 'class' in result and (not result['class'].split() or any(not re.fullmatch(PUBLIC_ID, v) for v in result['class'].split())):
            raise ValueError('Invalid public class')
        return result

    def _svg_attributes(self, tag, attrs):
        if '&' in self.get_starttag_text():
            raise ValueError('SVG entity references not allowed')
        values = self._attributes(attrs, svg=True)
        if set(values) - (self.SVG_COMMON | self.SVG_GEOMETRY[tag]):
            raise ValueError('Unregistered SVG attribute')
        for key, value in values.items():
            if re.search(r'(?:https?|data|javascript|file|ftp|blob):|//', value, re.I):
                raise ValueError('SVG URI not allowed')
            if key in ('aria-labelledby', 'aria-describedby'):
                if not value.split() or any(not re.fullmatch(PUBLIC_ID, v) for v in value.split()):
                    raise ValueError('SVG aria must reference internal IDs')
                self.svg_refs.update(value.split())
            elif key == 'role' and value not in ('img', 'presentation', 'none'):
                raise ValueError('Invalid SVG role')
            elif key == 'aria-hidden' and value not in ('true', 'false'):
                raise ValueError('Invalid SVG aria-hidden')
            elif key == 'transform':
                cursor = 0
                for match in re.finditer(r'(matrix|translate|scale|rotate|skewX|skewY)\(([^()]*)\)', value):
                    if value[cursor:match.start()].strip():
                        raise ValueError('Invalid SVG transform')
                    args = numeric_geometry(match[2])
                    counts = {'matrix': (6,), 'translate': (1, 2), 'scale': (1, 2), 'rotate': (1, 3), 'skewX': (1,), 'skewY': (1,)}
                    if len(args) not in counts[match[1]]:
                        raise ValueError('Invalid SVG transform arity')
                    cursor = match.end()
                if not cursor or value[cursor:].strip():
                    raise ValueError('Invalid SVG transform')
            elif key == 'd':
                if not re.fullmatch(r'[Mm][0-9MmLlHhVvCcSsQqTtAaZzEe+.,\s-]+', value) or not re.findall(NUMBER, value):
                    raise ValueError('Invalid SVG path geometry')
                import math
                if not all(math.isfinite(float(v)) for v in re.findall(NUMBER, value)):
                    raise ValueError('Non-finite SVG path geometry')
            elif key == 'viewbox':
                numbers = numeric_geometry(value, 4)
                if numbers[2] <= 0 or numbers[3] <= 0:
                    raise ValueError('Invalid SVG viewBox')
            elif key == 'points':
                numbers = numeric_geometry(value)
                if len(numbers) < 4 or len(numbers) % 2:
                    raise ValueError('Invalid SVG points')
            elif key in self.SVG_GEOMETRY[tag]:
                # Percent width/height is meaningful on the viewport only.
                number = numeric_geometry(value.removesuffix('%') if tag == 'svg' and key in ('width', 'height') else value, 1)[0]
                if key in ('width', 'height', 'rx', 'ry', 'pathlength', 'textlength') and number < 0:
                    raise ValueError('Negative SVG size')

    def _head_child(self, tag, values):
        raw = self.get_starttag_text()
        if not literal_head_markup(raw):
            raise ValueError('Head markup must be literal ASCII')
        if self.head_index >= len(self.HEAD_SHAPE):
            raise ValueError('Unexpected extra head child')
        expected_tag, expected = self.HEAD_SHAPE[self.head_index]
        if tag != expected_tag or set(values) != set(expected):
            raise ValueError('Invalid fixed head shape/order')
        for key, wanted in expected.items():
            if wanted is None:
                if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', values[key]):
                    raise ValueError('Invalid head build metadata')
            elif values[key] != wanted:
                raise ValueError('Invalid fixed head value')
        self.head_index += 1

    def _document_structure(self, tag, values):
        if tag == 'html':
            if self.stack or self.html_seen or not literal_head_markup(self.get_starttag_text()):
                raise ValueError('Single explicit HTML root required')
            self.html_seen = True
        elif tag == 'head':
            if self.stack != ['html'] or self.heads or not literal_head_markup(self.get_starttag_text()):
                raise ValueError('Invalid document head')
            self.heads = 1
        elif tag == 'body':
            if self.stack != ['html'] or not self.head_complete or self.body_seen:
                raise ValueError('Explicit body must follow the complete head')
            self.body_seen = True
        elif self.stack == ['html', 'head']:
            self._head_child(tag, values)
        elif tag in ('meta', 'link', 'title') or 'body' not in self.stack:
            raise ValueError('Only the fixed head and explicit body are supported')

    def handle_starttag(self, tag, attrs):
        if self.svg_stack or tag == 'svg':
            if tag not in SVG_TAGS or (self.svg_stack and (tag == 'svg' or self.svg_stack[-1] in ('title', 'desc', 'text'))):
                raise ValueError('Unregistered/integrating SVG element')
            if not self.svg_stack:
                if 'body' not in self.stack:
                    raise ValueError('Inline SVG requires HTML body content')
                self.svg_ids, self.svg_refs = set(), set()
            self._svg_attributes(tag, attrs)
            self.svg_stack.append(tag)
            self.stack.append(('svg', tag))
            return
        if tag not in self.HTML_TAGS or (self.stack and self.stack[-1] == 'title'):
            raise ValueError('Unregistered/active HTML element')
        values = self._attributes(attrs)
        allowed = self.COMMON | {
            'meta': {'name', 'content', 'http-equiv', 'charset'},
            'link': {'rel', 'href', 'media'}, 'a': {'href', 'rel', 'target'},
            'time': {'datetime'}, 'details': {'open'}, 'ol': {'start', 'reversed'},
            'th': {'scope', 'colspan', 'rowspan'}, 'td': {'colspan', 'rowspan'},
            'col': {'span'}, 'colgroup': {'span'},
        }.get(tag, set())
        if any(k not in allowed and not re.fullmatch(r'data-[a-z0-9_-]+', k) for k in values):
            raise ValueError('Unregistered HTML attribute')
        self._document_structure(tag, values)
        if tag == 'meta' and 'http-equiv' in values:
            content = values.get('content', '')
            if self.csp or not content.isascii() or content.encode('ascii') != HTML_CSP.encode('ascii'):
                raise ValueError('CSP must match exact ASCII policy bytes')
            self.csp = True
        if tag == 'link' and (values.get('rel') != 'stylesheet' or values.get('href') != 'style.css'):
            raise ValueError('Only the edition stylesheet is allowed')
        if tag == 'a' and 'href' in values:
            from urllib.parse import urlsplit
            url = values['href']
            if url != url.strip() or '\\' in url or any(ord(c) < 32 for c in url):
                raise ValueError('Invalid HTML link')
            parsed = urlsplit(url)
            if parsed.scheme:
                if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or not {'noreferrer', 'noopener'} <= set(values.get('rel', '').split()):
                    raise ValueError('Public external link requires HTTPS/no-referrer')
            elif parsed.netloc or ':' in url or '%' in url:
                raise ValueError('Invalid local HTML link')
        if tag not in HTML_VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        expected = ('svg', tag) if self.svg_stack else tag
        if not self.stack or self.stack[-1] != expected:
            raise ValueError('Unbalanced HTML/SVG explicit end tag')
        if tag == 'head':
            if self.head_index != len(self.HEAD_SHAPE):
                raise ValueError('Incomplete fixed head')
            self.head_complete = True
        if tag == 'html' and not self.body_seen:
            raise ValueError('Missing explicit document body')
        self.stack.pop()
        if self.svg_stack:
            self.svg_stack.pop()
            if not self.svg_stack and not self.svg_refs <= self.svg_ids:
                raise ValueError('SVG aria reference outside its SVG')

    def handle_data(self, data):
        if 'body' not in self.stack and not (self.stack and self.stack[-1] == 'title'):
            if any(c not in HTML_SPACE for c in data):
                raise ValueError('Non-whitespace text outside body/head title')
        if self.svg_stack and self.svg_stack[-1] not in ('text', 'title', 'desc') and data.strip():
            raise ValueError('SVG text requires a text/title/desc element')

    def handle_entityref(self, name):
        if self.svg_stack:
            raise ValueError('SVG entities not allowed')
        if 'body' not in self.stack and not (self.stack and self.stack[-1] == 'title'):
            raise ValueError('Entity outside body/head title')

    def handle_charref(self, name):
        self.handle_entityref(name)

    def handle_comment(self, data):
        if 'body' not in self.stack:
            raise ValueError('Comments outside body are not supported')

    def handle_decl(self, decl):
        if decl.lower() != 'doctype html' or self.stack or self.html_seen or self.doctype_seen:
            raise ValueError('DTD/entity declarations or misplaced DOCTYPE not allowed')
        self.doctype_seen = True

    def unknown_decl(self, data):
        raise ValueError('XML/unknown declarations not allowed')

    def handle_pi(self, data):
        raise ValueError('Processing instructions not allowed')

    def finish(self):
        self.close()
        if self.stack or not self.csp or self.heads != 1 or not self.head_complete or not self.body_seen:
            raise ValueError('Complete HTML with expected CSP required')


def validate_html_presentation(data):
    text = data.decode('utf-8')
    if re.search(r'<!\s*entity\b', text, re.I):
        raise ValueError('Entity declarations not allowed')
    parser = HTMLPresentation()
    parser.feed(text)
    parser.finish()


def validate_png(data):
    if data[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError('Invalid PNG signature')
    offset = 8
    chunks = []
    compressed = bytearray()
    while offset < len(data):
        if offset+12 > len(data):
            raise ValueError('Truncated PNG')
        size, = struct.unpack('>I', data[offset:offset+4])
        kind = data[offset+4:offset+8]
        end = offset+12+size
        if end > len(data) or zlib.crc32(data[offset+4:end-4]) != struct.unpack('>I', data[end-4:end])[0]:
            raise ValueError('Invalid PNG chunk')
        payload = data[offset+8:end-4]
        # No private/unregistered ancillary channels. Keep bytes or reject;
        # never silently strip metadata before hashing/publication.
        allowed = {b'IHDR', b'PLTE', b'IDAT', b'IEND', b'sRGB', b'gAMA', b'cHRM', b'pHYs', b'tRNS'}
        if kind not in allowed:
            raise ValueError('Private or unknown PNG metadata chunk')
        if kind == b'sRGB' and (len(payload) != 1 or payload[0] > 3):
            raise ValueError('Invalid PNG sRGB metadata')
        if kind == b'gAMA' and (len(payload) != 4 or not int.from_bytes(payload, 'big')):
            raise ValueError('Invalid PNG gamma metadata')
        if kind == b'cHRM' and len(payload) != 32:
            raise ValueError('Invalid PNG chromaticity metadata')
        if kind == b'pHYs' and (len(payload) != 9 or payload[-1] > 1):
            raise ValueError('Invalid PNG density metadata')
        if kind == b'PLTE' and (not payload or len(payload) % 3 or len(payload) > 768):
            raise ValueError('Invalid PNG palette')
        if kind == b'tRNS' and (not chunks or color not in (0, 2, 3) or
                (color == 0 and len(payload) != 2) or (color == 2 and len(payload) != 6) or
                (color == 3 and not 1 <= len(payload) <= 256)):
            raise ValueError('Invalid PNG transparency')
        if kind == b'IDAT':
            compressed.extend(payload)
        chunks.append(kind)
        if kind == b'IHDR':
            if len(payload) != 13 or struct.unpack('>II', payload[:8]) != (1080, 1350):
                raise ValueError('PNG must be 1080x1350')
            depth, color, compression, filtering, interlace = payload[8:]
            if depth not in (1, 2, 4, 8, 16) or color not in (0, 2, 3, 4, 6) or compression or filtering or interlace not in (0, 1):
                raise ValueError('Invalid PNG header')
        offset = end
        if kind == b'IEND':
            if payload or offset != len(data):
                raise ValueError('Trailing PNG data')
            break
    if not chunks or chunks[0] != b'IHDR' or chunks[-1] != b'IEND' or chunks.count(b'IHDR') != 1 or not compressed:
        raise ValueError('Incomplete PNG')
    decoder = zlib.decompressobj()
    # Bound decompression even for malicious deflate payloads (16-bit RGBA maximum).
    raw = decoder.decompress(bytes(compressed), 12_000_000)
    if not raw or len(raw) >= 12_000_000 or not decoder.eof or decoder.unused_data:
        raise ValueError('Invalid PNG pixels')
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color]
    if depth not in ({0: (1, 2, 4, 8, 16), 2: (8, 16), 3: (1, 2, 4, 8), 4: (8, 16), 6: (8, 16)}[color]):
        raise ValueError('Invalid PNG bit depth')
    if color == 3 and b'PLTE' not in chunks:
        raise ValueError('PNG palette missing')
    passes = [(0, 0, 1, 1)] if not interlace else [
        (0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4),
        (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2)]
    cursor = 0
    for x, y, dx, dy in passes:
        width, height = (1080-x+dx-1)//dx, (1350-y+dy-1)//dy
        stride = (width*channels*depth+7)//8+1
        for _ in range(height):
            if cursor >= len(raw) or raw[cursor] > 4:
                raise ValueError('Invalid PNG scanline')
            cursor += stride
    if cursor != len(raw):
        raise ValueError('PNG pixel length mismatch')


def validate_market_bytes(approved, files):
    if files['robots.txt'] != ROBOTS:
        raise ValueError('Invalid robots.txt')
    prefix = approved['path_prefix']
    latest = max(approved['entries'].values(), key=lambda e: (market_order(e['issue_id']), e['revision']))
    for entry in approved['entries'].values():
        if entry.get('presentation') == 'html-v1':
            validate_html_presentation(files[entry['path']+'/index.html'])
            validate_css(files[entry['path']+'/style.css'])
    for name, data in files.items():
        if name.endswith('.png'):
            validate_png(data)
        if name.endswith('.html'):
            page = HTMLMetadata()
            page.feed(data.decode('utf-8'))
            robots = {v.strip().lower() for v in page.meta.get('robots', '').split(',')}
            if not {'noindex', 'nofollow'} <= robots:
                raise ValueError('Every market HTML requires noindex,nofollow')
            if name in ('index.html', '404.html'):
                if prefix.rstrip('/') in data.decode('utf-8'):
                    raise ValueError('Root page exposes caller token')
            else:
                entry = next((e for e in approved['entries'].values() if name == e['path']+'/index.html'), latest)
                if page.meta.get('market-build-id') != entry['build_id']:
                    raise ValueError('Market build metadata mismatch')
                if name in (prefix+'index.html', prefix+'archive/index.html', prefix+'latest/index.html'):
                    expected = {latest['path']} if name == prefix+'latest/index.html' else {e['path'] for e in approved['entries'].values()}
                    from posixpath import normpath, dirname
                    links = set()
                    for href in page.links:
                        if not href or href.startswith(('/', '#')) or ':' in href or '?' in href or '#' in href or '%' in href or '\\' in href:
                            raise ValueError('Index links must be local relative edition links')
                        links.add(normpath(dirname(name)+'/'+href).removesuffix('/index.html').rstrip('/'))
                    if links != expected:
                        raise ValueError('Latest/archive edition links mismatch')


def validate_public_metadata(approved, schema):
    """Strict recursive shapes, including fields later projected into approvals."""
    common = {'schema_version', 'entries', 'files', 'archive', 'site_hash', 'asset', 'release_tag'}
    allowed = common | ({'path_prefix', 'retention'} if schema == MARKET_SCHEMA else
                        {'optional_assets', 'test_only', 'status', 'audience', 'base_path', 'issues'})
    if set(approved) - allowed:
        raise ValueError('Forbidden public manifest field')
    for field in ('asset', 'release_tag', 'status', 'audience', 'base_path'):
        if field in approved and not isinstance(approved[field], str):
            raise ValueError('Invalid public scalar field')
    if 'test_only' in approved and type(approved['test_only']) is not bool:
        raise ValueError('Invalid test marker')
    if 'issues' in approved and (not isinstance(approved['issues'], list) or any(
            not isinstance(v, str) or not re.fullmatch(r'[0-9]{4}-W[0-9]{2}', v) for v in approved['issues'])):
        raise ValueError('Invalid public issue list')
    files = approved['files']
    if not isinstance(files, dict):
        raise ValueError('Invalid public file map')
    for name, item in files.items():
        if not isinstance(name, str) or not isinstance(item, dict) or set(item) != {'bytes', 'sha256'}:
            raise ValueError('Forbidden file metadata field')
        if type(item['bytes']) is not int or item['bytes'] < 0 or not isinstance(item['sha256'], str) or not re.fullmatch(r'[a-f0-9]{64}', item['sha256']):
            raise ValueError('Invalid file metadata')
    if 'archive' in approved:
        item = approved['archive']
        if not isinstance(item, dict) or set(item) != {'file', 'bytes', 'sha256'}:
            raise ValueError('Forbidden archive metadata field')
        if not isinstance(item['file'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.zip', item['file']) or type(item['bytes']) is not int or item['bytes'] < 1 or not isinstance(item['sha256'], str) or not re.fullmatch(r'[a-f0-9]{64}', item['sha256']):
            raise ValueError('Invalid archive metadata')
    if 'site_hash' in approved and (not isinstance(approved['site_hash'], str) or not re.fullmatch(r'[a-f0-9]{64}', approved['site_hash'])):
        raise ValueError('Invalid site hash')
    if not isinstance(approved['entries'], dict):
        raise ValueError('Invalid public entries')
    if schema == MARKET_SCHEMA:
        for entry in approved['entries'].values():
            market_entry_files(entry)


def validate_contract(approved, *, legacy=False):
    """Explicit schema dispatch; legacy file-only reads require an opt-in."""
    schema = approved.get('schema_version')
    if schema == MARKET_SCHEMA:
        validate_public_metadata(approved, schema)
        validate_market(approved)
        return
    if schema != 2:
        if legacy and schema in (None, 1) and 'entries' not in approved and 'issues' not in approved:
            return
        raise ValueError('Unknown schema; legacy requires explicit file-only mode')
    validate_public_metadata(approved, schema)
    expected = {'index.html', '404.html'}
    entries = approved['entries']
    if set(approved['optional_assets']) != set(entries):
        raise ValueError('Asset declarations must match revisions')
    for key, entry in entries.items():
        if not isinstance(entry, dict) or set(entry) != {'issue_id', 'revision', 'path', 'build_id', 'ranks', 'date', 'bonus'}:
            raise ValueError('Forbidden schema2 public entry field')
        if any(not isinstance(entry[k], str) for k in ('issue_id', 'path', 'build_id', 'date')) or type(entry['revision']) is not int or entry['revision'] < 1 or type(entry['bonus']) is not int or entry['bonus'] < 0:
            raise ValueError('Invalid schema2 public entry type')
        revision = entry['revision']
        if key != entry['issue_id'] + ('' if revision == 1 else f'-r{revision}'):
            raise ValueError('Schema2 revision key mismatch')
        if not isinstance(entry['ranks'], list):
            raise ValueError('Invalid detail ranks')
        issue = entry['issue_id']; prefix = entry['path'].rstrip('/')
        if not re.fullmatch(r'\d{4}-W\d{2}', issue) or not re.fullmatch(r'posts/\d{4}-W\d{2}(?:/revisions/r[1-9]\d*)?', prefix):
            raise ValueError('Invalid issue path')
        if prefix != 'posts/' + issue + ('' if revision == 1 else f'/revisions/r{revision}'):
            raise ValueError('Issue/path mismatch')
        assets = approved['optional_assets'][key]
        if assets not in ([], ['cover.png']):
            raise ValueError('Undeclared or unsupported optional assets')
        expected.update({prefix+'/index.html', prefix+'/assets/site.css'})
        ranks = entry['ranks']
        if not ranks or len(set(ranks)) != len(ranks) or any(type(n) is not int or not 1 <= n <= 999 for n in ranks):
            raise ValueError('Invalid detail rank list')
        expected.update(prefix+f'/details/{n:02d}.html' for n in ranks)
        expected.update(prefix+'/'+a for a in assets)
    if expected != set(approved['files']):
        raise ValueError('Files do not match declared asset contract')


def release_url(approved):
    validate_contract(approved)
    tag, asset = approved['release_tag'], approved['asset']
    if not re.fullmatch(r'(?:[0-9]{4}-W[0-9]{2}|[0-9]{4}-[0-9]{2}-[0-9]{2}-(?:AM|PM)(?:-SPECIAL)?)-r[1-9][0-9]*-[a-f0-9]{12}', tag) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.zip', asset):
        raise ValueError('Invalid approved release selector')
    issue = tag.rsplit('-r', 1)[0]
    if approved['schema_version'] == MARKET_SCHEMA:
        revision = int(tag.rsplit('-r', 1)[1].split('-', 1)[0])
        if not valid_market_id(issue) or not any(e['issue_id'] == issue and e['revision'] == revision for e in approved['entries'].values()):
            raise ValueError('Market release requires a declared edition/revision')
    elif not re.fullmatch(r'[0-9]{4}-W[0-9]{2}', issue):
        raise ValueError('Weekly release requires weekly ID')
    return 'https://github.com/kimG-bit/hermes-market-briefing/releases/download/' + tag + '/' + asset


def download_approved(manifest, destination):
    approved = json.loads(manifest.read_text())
    url = release_url(approved)
    if destination.exists():
        raise ValueError('Download target exists')
    if not 0 < approved['archive']['bytes'] <= 20_000_000:
        raise ValueError('Download size limit exceeded')
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read(approved['archive']['bytes'] + 1)
    if len(data) != approved['archive']['bytes'] or hashlib.sha256(data).hexdigest() != approved['archive']['sha256']:
        raise ValueError('Downloaded archive hash mismatch')
    destination.write_bytes(data)


def verify(bundle, manifest, output, *, archive_pin=None, legacy=False):
    approved = json.loads(manifest.read_text())
    if output.exists():
        raise ValueError('Output already exists')
    container = approved.get('archive') or archive_pin
    if not container:
        raise ValueError('Legacy file-only manifest requires an independently approved archive pin')
    if bundle.stat().st_size != container['bytes'] or hashlib.sha256(bundle.read_bytes()).hexdigest() != container['sha256']:
        raise ValueError('Archive approval mismatch')
    validate_contract(approved, legacy=legacy)
    expected = approved['files']
    if not expected or len(expected) > 1000:
        raise ValueError('Invalid allowlist')
    total = sum(item['bytes'] for item in expected.values())
    if total > 20_000_000:
        raise ValueError('Approved size limit exceeded')
    validated = {}
    with ZipFile(bundle) as z:
        names = z.namelist()
        if len(set(names)) != len(names) or set(names) != set(expected):
            raise ValueError('ZIP entries differ from allowlist')
        for info in z.infolist():
            name = info.filename
            path = PurePosixPath(name)
            mode = stat.S_IFMT(info.external_attr >> 16)
            if path.is_absolute() or '..' in path.parts or '\\' in name or str(path) != name or info.is_dir() or mode not in (0, stat.S_IFREG):
                raise ValueError('Unsafe archive entry')
            item = expected[name]
            if info.file_size != item['bytes'] or info.file_size > total:
                raise ValueError('File size mismatch')
            data = z.read(info)
            if hashlib.sha256(data).hexdigest() != item['sha256']:
                raise ValueError('File hash mismatch')
            validated[name] = data
    if approved.get('schema_version') == MARKET_SCHEMA:
        validate_market_bytes(approved, validated)
    output.mkdir(parents=True)
    for name, data in validated.items():
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return len(validated)


if __name__ == '__main__':
    if sys.argv[1] == '--download':
        download_approved(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        count = verify(*(Path(p) for p in sys.argv[1:]))
        print(json.dumps({'verified_files': count}))
