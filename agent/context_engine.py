"""
Ozz — Context Engineering Module
Filters ~90% of redundant page states before sending to the LLM.

Inspired by DEF CON 34 AI Village poster:
"Beyond CTFs: Engineering AI Agents for Real-World Web Pentesting" (BugBase)

Pipeline:
  Raw HTML → DOM Extraction → Accessibility Tree → Network Normalization
  → Request Dedup → Page Similarity Clustering → Category Memory → Filtered Context
"""

import hashlib
import json
import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode

logger = logging.getLogger("ozz.context_engine")

# ============================================================
# Data Structures
# ============================================================


@dataclass
class DOMElement:
    """Extracted DOM element."""
    tag: str
    attributes: dict[str, str] = field(default_factory=dict)
    text: str = ""
    children: list["DOMElement"] = field(default_factory=list)
    depth: int = 0

    def structural_hash(self) -> str:
        """Hash of structure only (ignoring text content)."""
        sig = f"{self.tag}:{','.join(sorted(self.attributes.keys()))}"
        child_sigs = "".join(c.structural_hash() for c in self.children)
        return hashlib.md5(f"{sig}|{child_sigs}".encode()).hexdigest()[:12]


@dataclass
class FormField:
    """Extracted form field."""
    name: str
    input_type: str  # text, password, hidden, submit, etc.
    value: str = ""
    required: bool = False
    label: str = ""


@dataclass
class ExtractedForm:
    """Extracted HTML form."""
    action: str = ""
    method: str = "GET"
    fields: list[FormField] = field(default_factory=list)
    csrf_token: Optional[str] = None
    csrf_field_name: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "method": self.method,
            "fields": [{"name": f.name, "type": f.input_type, "value": f.value} for f in self.fields],
            "csrf_token": self.csrf_token,
            "csrf_field_name": self.csrf_field_name,
        }


@dataclass
class PageState:
    """Structured representation of a page state."""
    url: str
    title: str = ""
    forms: list[ExtractedForm] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    headings: list[str] = field(default_factory=list)
    landmarks: list[str] = field(default_factory=list)  # nav, main, aside, header, footer
    interactive_elements: list[str] = field(default_factory=list)  # buttons, inputs
    meta_tags: dict[str, str] = field(default_factory=dict)
    structural_hash: str = ""
    content_hash: str = ""
    category: str = "unknown"
    timestamp: float = field(default_factory=time.time)
    raw_html_size: int = 0

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "title": self.title,
            "forms": [f.to_dict() for f in self.forms],
            "links_count": len(self.links),
            "links_sample": self.links[:10],
            "scripts_count": len(self.scripts),
            "headings": self.headings,
            "landmarks": self.landmarks,
            "interactive_count": len(self.interactive_elements),
            "meta_tags": self.meta_tags,
            "structural_hash": self.structural_hash,
            "content_hash": self.content_hash,
            "category": self.category,
            "raw_html_size": self.raw_html_size,
        }


@dataclass
class NormalizedRequest:
    """Normalized HTTP request for deduplication."""
    method: str
    endpoint: str  # URL path without query params
    param_names: frozenset[str]
    status_code: int = 0
    response_size: int = 0
    content_type: str = ""
    count: int = 1  # How many times this pattern was seen

    def signature(self) -> str:
        return f"{self.method}:{self.endpoint}:{','.join(sorted(self.param_names))}"

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "endpoint": self.endpoint,
            "param_names": sorted(self.param_names),
            "status_code": self.status_code,
            "response_size": self.response_size,
            "content_type": self.content_type,
            "count": self.count,
        }


@dataclass
class ClusteredPage:
    """A cluster of similar pages."""
    structural_hash: str
    category: str
    representative_url: str
    urls: list[str] = field(default_factory=list)
    count: int = 1
    representative_state: Optional[PageState] = None

    def to_dict(self) -> dict:
        return {
            "structural_hash": self.structural_hash,
            "category": self.category,
            "representative_url": self.representative_url,
            "urls": self.urls[:5],
            "count": self.count,
        }


# ============================================================
# DOM Extraction
# ============================================================


class DOMExtractor:
    """Parse HTML into structured DOM tree, extract forms/inputs/links/scripts."""

    # Regex-based parsing (no lxml dependency for portability)
    _TAG_RE = re.compile(r'<(\w+)([^>]*)>(.*?)</\1>', re.DOTALL | re.IGNORECASE)
    _SELF_CLOSING_RE = re.compile(r'<(\w+)([^>]*)/?>', re.IGNORECASE)
    _ATTR_RE = re.compile(r'(\w[\w-]*)\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
    _FORM_RE = re.compile(r'<form([^>]*)>(.*?)</form>', re.DOTALL | re.IGNORECASE)
    _INPUT_RE = re.compile(r'<input([^>]*)/?>', re.IGNORECASE)
    _SELECT_RE = re.compile(r'<select([^>]*)>(.*?)</select>', re.DOTALL | re.IGNORECASE)
    _TEXTAREA_RE = re.compile(r'<textarea([^>]*)>(.*?)</textarea>', re.DOTALL | re.IGNORECASE)
    _LINK_RE = re.compile(r'<a\s+[^>]*href=["\']([^"\']*)["\']', re.IGNORECASE)
    _SCRIPT_RE = re.compile(r'<script[^>]*src=["\']([^"\']*)["\']', re.IGNORECASE)
    _TITLE_RE = re.compile(r'<title[^>]*>(.*?)</title>', re.DOTALL | re.IGNORECASE)
    _HEADING_RE = re.compile(r'<(h[1-6])[^>]*>(.*?)</\1>', re.DOTALL | re.IGNORECASE)
    _META_RE = re.compile(r'<meta\s+([^>]*?)/?>', re.IGNORECASE)
    _LANDMARK_RE = re.compile(r'<(nav|main|aside|header|footer|section|article)\b[^>]*>', re.IGNORECASE)
    _BUTTON_RE = re.compile(r'<button[^>]*>(.*?)</button>', re.DOTALL | re.IGNORECASE)
    _CSRF_RE = re.compile(
        r'<input[^>]*name=["\']((?:csrf|_token|authenticity_token|__RequestVerificationToken|'
        r'_csrf|csrf_token|csrfmiddlewaretoken)[^"\']*)["\'][^>]*value=["\']([^"\']*)["\']',
        re.IGNORECASE,
    )
    _CSRF_META_RE = re.compile(
        r'<meta[^>]*name=["\']((?:csrf|_token|csrf-token|xsrf-token)[^"\']*)["\'][^>]*content=["\']([^"\']*)["\']',
        re.IGNORECASE,
    )

    @classmethod
    def extract(cls, html: str, url: str = "") -> PageState:
        """Extract structured page state from HTML."""
        state = PageState(url=url, raw_html_size=len(html))

        # Title
        title_match = cls._TITLE_RE.search(html)
        state.title = title_match.group(1).strip() if title_match else ""

        # Forms
        state.forms = cls._extract_forms(html)

        # Links
        state.links = list(set(cls._LINK_RE.findall(html)))

        # Scripts
        state.scripts = list(set(cls._SCRIPT_RE.findall(html)))

        # Headings
        for m in cls._HEADING_RE.finditer(html):
            tag, text = m.group(1), re.sub(r'<[^>]+>', '', m.group(2)).strip()
            if text:
                state.headings.append(f"{tag}: {text}")

        # Landmarks
        state.landmarks = list(set(m.group(1).lower() for m in cls._LANDMARK_RE.finditer(html)))

        # Interactive elements (buttons)
        state.interactive_elements = [
            re.sub(r'<[^>]+>', '', m.group(1)).strip()
            for m in cls._BUTTON_RE.finditer(html)
            if re.sub(r'<[^>]+>', '', m.group(1)).strip()
        ]

        # Meta tags
        for m in cls._META_RE.finditer(html):
            attrs = cls._parse_attrs(m.group(1))
            name = attrs.get("name", attrs.get("property", attrs.get("http-equiv", "")))
            content = attrs.get("content", "")
            if name and content:
                state.meta_tags[name] = content

        # Structural hash (tag skeleton only)
        skeleton = cls._extract_skeleton(html)
        state.structural_hash = hashlib.md5(skeleton.encode()).hexdigest()[:16]

        # Content hash (full content)
        state.content_hash = hashlib.md5(html.encode()).hexdigest()[:16]

        return state

    @classmethod
    def _extract_forms(cls, html: str) -> list[ExtractedForm]:
        """Extract all forms with their fields and CSRF tokens."""
        forms = []
        for m in cls._FORM_RE.finditer(html):
            attrs = cls._parse_attrs(m.group(1))
            form_html = m.group(2)

            form = ExtractedForm(
                action=attrs.get("action", ""),
                method=attrs.get("method", "GET").upper(),
            )

            # Extract CSRF token
            csrf_match = cls._CSRF_RE.search(form_html)
            if csrf_match:
                form.csrf_field_name = csrf_match.group(1)
                form.csrf_token = csrf_match.group(2)
            else:
                # Check meta CSRF
                csrf_meta = cls._CSRF_META_RE.search(html)
                if csrf_meta:
                    form.csrf_field_name = csrf_meta.group(1)
                    form.csrf_token = csrf_meta.group(2)

            # Extract input fields
            for inp in cls._INPUT_RE.finditer(form_html):
                inp_attrs = cls._parse_attrs(inp.group(1))
                field_name = inp_attrs.get("name", "")
                if field_name:
                    form.fields.append(FormField(
                        name=field_name,
                        input_type=inp_attrs.get("type", "text"),
                        value=inp_attrs.get("value", ""),
                        required="required" in inp.group(1).lower(),
                    ))

            # Extract textarea fields
            for ta in cls._TEXTAREA_RE.finditer(form_html):
                ta_attrs = cls._parse_attrs(ta.group(1))
                field_name = ta_attrs.get("name", "")
                if field_name:
                    form.fields.append(FormField(
                        name=field_name,
                        input_type="textarea",
                        value=ta.group(2).strip(),
                    ))

            # Extract select fields
            for sel in cls._SELECT_RE.finditer(form_html):
                sel_attrs = cls._parse_attrs(sel.group(1))
                field_name = sel_attrs.get("name", "")
                if field_name:
                    form.fields.append(FormField(
                        name=field_name,
                        input_type="select",
                    ))

            forms.append(form)
        return forms

    @classmethod
    def _extract_skeleton(cls, html: str) -> str:
        """Extract HTML skeleton (tag names and nesting, no content)."""
        # Remove content between tags, keep structure
        clean = re.sub(r'>\s+<', '><', html)
        # Remove attributes
        clean = re.sub(r'<(\w+)\s+[^>]*>', r'<\1>', clean)
        # Remove text content
        clean = re.sub(r'>([^<]+)<', '><', clean)
        # Keep only tag structure
        tags = re.findall(r'</?\w+/??>', clean)
        return "".join(tags)

    @staticmethod
    def _parse_attrs(attr_string: str) -> dict[str, str]:
        """Parse HTML attributes from attribute string."""
        return dict(DOMExtractor._ATTR_RE.findall(attr_string))


# ============================================================
# Accessibility Tree Parser
# ============================================================


class AccessibilityTreeParser:
    """Extract semantic structure: headings, landmarks, interactive elements."""

    _ROLE_MAP = {
        "nav": "navigation",
        "main": "main",
        "aside": "complementary",
        "header": "banner",
        "footer": "contentinfo",
        "section": "region",
        "article": "article",
        "form": "form",
        "table": "table",
        "button": "button",
        "a": "link",
        "input": "textbox",
        "select": "listbox",
        "textarea": "textbox",
        "h1": "heading-1",
        "h2": "heading-2",
        "h3": "heading-3",
        "h4": "heading-4",
        "h5": "heading-5",
        "h6": "heading-6",
        "img": "img",
        "label": "label",
        "dialog": "dialog",
        "details": "details",
        "summary": "summary",
    }

    @classmethod
    def parse(cls, html: str) -> dict[str, list[str]]:
        """Parse HTML into accessibility-tree-like structure."""
        tree: dict[str, list[str]] = {
            "headings": [],
            "landmarks": [],
            "interactive": [],
            "links": [],
            "images": [],
            "labels": [],
        }

        # Headings
        for m in re.finditer(r'<(h[1-6])[^>]*>(.*?)</\1>', html, re.DOTALL | re.IGNORECASE):
            text = re.sub(r'<[^>]+>', '', m.group(2)).strip()
            if text:
                tree["headings"].append(f"[{m.group(1).upper()}] {text[:100]}")

        # Landmarks
        for m in re.finditer(r'<(nav|main|aside|header|footer|section|article)\b[^>]*>', html, re.IGNORECASE):
            role = cls._ROLE_MAP.get(m.group(1).lower(), m.group(1))
            attrs = DOMExtractor._parse_attrs(m.group(2) if len(m.groups()) > 1 else "")
            label = attrs.get("aria-label", attrs.get("title", ""))
            tree["landmarks"].append(f"{role}" + (f" ({label})" if label else ""))

        # Interactive elements
        for m in re.finditer(r'<(button|input|select|textarea|a)\b([^>]*)>', html, re.IGNORECASE):
            tag = m.group(1).lower()
            attrs = DOMExtractor._parse_attrs(m.group(2))
            desc_parts = [tag]
            if attrs.get("type"):
                desc_parts.append(f"type={attrs['type']}")
            if attrs.get("name"):
                desc_parts.append(f"name={attrs['name']}")
            if attrs.get("placeholder"):
                desc_parts.append(f"placeholder={attrs['placeholder']}")
            if attrs.get("aria-label"):
                desc_parts.append(f"label={attrs['aria-label']}")
            tree["interactive"].append(" | ".join(desc_parts))

        # Links with text
        for m in re.finditer(r'<a\s+[^>]*href=["\']([^"\']*)["\'][^>]*>(.*?)</a>', html, re.DOTALL | re.IGNORECASE):
            href = m.group(1)
            text = re.sub(r'<[^>]+>', '', m.group(2)).strip()[:50]
            if href and not href.startswith('#') and not href.startswith('javascript:'):
                tree["links"].append(f"{href}" + (f" [{text}]" if text else ""))

        # Images
        for m in re.finditer(r'<img\s+[^>]*>', html, re.IGNORECASE):
            attrs = DOMExtractor._parse_attrs(m.group(0))
            alt = attrs.get("alt", "")
            src = attrs.get("src", "")[:80]
            tree["images"].append(f"src={src} alt={alt}")

        return tree


# ============================================================
# Network Capture & Normalization
# ============================================================


class NetworkCapture:
    """Intercept, normalize, and deduplicate HTTP requests/responses."""

    def __init__(self):
        self._requests: list[dict[str, Any]] = []
        self._normalized: dict[str, NormalizedRequest] = {}

    def capture(self, method: str, url: str, status_code: int = 0,
                response_size: int = 0, content_type: str = "",
                request_body: str = ""):
        """Capture an HTTP request/response pair."""
        parsed = urlparse(url)
        params = set(parse_qs(parsed.query).keys())

        entry = {
            "method": method.upper(),
            "url": url,
            "path": parsed.path,
            "params": sorted(params),
            "status_code": status_code,
            "response_size": response_size,
            "content_type": content_type,
            "timestamp": time.time(),
        }
        self._requests.append(entry)

        # Update normalized view
        sig = f"{method.upper()}:{parsed.path}:{','.join(sorted(params))}"
        if sig in self._normalized:
            self._normalized[sig].count += 1
            self._normalized[sig].status_code = status_code
            self._normalized[sig].response_size = response_size
        else:
            self._normalized[sig] = NormalizedRequest(
                method=method.upper(),
                endpoint=parsed.path,
                param_names=frozenset(params),
                status_code=status_code,
                response_size=response_size,
                content_type=content_type,
            )

    def get_normalized(self) -> list[NormalizedRequest]:
        """Get deduplicated request list."""
        return list(self._normalized.values())

    def get_raw(self, limit: int = 50) -> list[dict]:
        """Get raw request list (limited)."""
        return self._requests[-limit:]

    def get_endpoints(self) -> list[str]:
        """Get unique endpoint paths."""
        return sorted(set(r.endpoint for r in self._normalized.values()))

    def get_stats(self) -> dict:
        """Get network capture statistics."""
        total = len(self._requests)
        unique = len(self._normalized)
        return {
            "total_requests": total,
            "unique_endpoints": unique,
            "dedup_ratio": round(1 - (unique / max(total, 1)), 2),
            "methods": dict(defaultdict(int, {
                r.method: sum(1 for x in self._requests if x["method"] == r.method)
                for r in self._normalized.values()
            })),
        }

    def to_context_string(self, max_entries: int = 20) -> str:
        """Format normalized requests as context string for LLM."""
        entries = sorted(self._normalized.values(), key=lambda r: r.count, reverse=True)
        lines = []
        for e in entries[:max_entries]:
            line = f"{e.method} {e.endpoint}"
            if e.param_names:
                line += f" params=[{','.join(sorted(e.param_names))}]"
            line += f" → {e.status_code} ({e.response_size}B)"
            if e.count > 1:
                line += f" [x{e.count}]"
            lines.append(line)
        return "\n".join(lines) if lines else "No network requests captured."


# ============================================================
# Page Similarity Clustering
# ============================================================


class PageSimilarityClusterer:
    """Detect when pages are essentially the same (different content, same structure)."""

    def __init__(self):
        self._clusters: dict[str, ClusteredPage] = {}

    def add_page(self, state: PageState) -> ClusteredPage:
        """Add a page state and return its cluster."""
        shash = state.structural_hash

        if shash in self._clusters:
            cluster = self._clusters[shash]
            cluster.count += 1
            if state.url not in cluster.urls:
                cluster.urls.append(state.url)
            # Keep the most informative page as representative
            if len(state.forms) > len(cluster.representative_state.forms if cluster.representative_state else []):
                cluster.representative_state = state
                cluster.representative_url = state.url
        else:
            category = self._categorize_page(state)
            cluster = ClusteredPage(
                structural_hash=shash,
                category=category,
                representative_url=state.url,
                urls=[state.url],
                representative_state=state,
            )
            self._clusters[shash] = cluster

        state.category = cluster.category
        return cluster

    def get_clusters(self) -> list[ClusteredPage]:
        """Get all page clusters."""
        return list(self._clusters.values())

    def get_by_category(self, category: str) -> list[ClusteredPage]:
        """Get clusters filtered by category."""
        return [c for c in self._clusters.values() if c.category == category]

    def get_summary(self) -> dict:
        """Get clustering summary."""
        categories = defaultdict(int)
        for c in self._clusters.values():
            categories[c.category] += c.count
        return {
            "total_clusters": len(self._clusters),
            "total_pages": sum(c.count for c in self._clusters.values()),
            "categories": dict(categories),
            "dedup_ratio": round(1 - len(self._clusters) / max(sum(c.count for c in self._clusters.values()), 1), 2),
        }

    @staticmethod
    def _categorize_page(state: PageState) -> str:
        """Categorize a page based on its characteristics."""
        url_lower = state.url.lower()
        title_lower = state.title.lower()
        headings_text = " ".join(state.headings).lower()

        # Login pages
        if any(kw in url_lower for kw in ("/login", "/signin", "/auth", "/session")):
            return "login"
        has_password = any(f.input_type == "password" for f_form in state.forms for f in f_form.fields)
        if has_password:
            return "login"

        # Admin pages
        if any(kw in url_lower for kw in ("/admin", "/dashboard", "/manage", "/panel")):
            return "admin"

        # API endpoints
        if any(kw in url_lower for kw in ("/api/", "/graphql", "/rest/", "/v1/", "/v2/")):
            return "api"

        # Error pages
        if any(kw in title_lower for kw in ("error", "not found", "404", "500", "forbidden", "403")):
            return "error"
        if any(kw in headings_text for kw in ("error", "not found", "forbidden")):
            return "error"

        # Registration/signup
        if any(kw in url_lower for kw in ("/register", "/signup", "/sign-up", "/create")):
            return "registration"

        # File/resource pages
        if any(kw in url_lower for kw in ("/static/", "/assets/", "/uploads/", "/files/")):
            return "static"

        # Search pages
        if any(kw in url_lower for kw in ("/search", "/query", "/find")):
            return "search"

        # Index/home
        if url_lower.rstrip("/").endswith(("", "/index", "/index.html", "/index.php", "/home")):
            return "index"

        # Forms present but not login
        if state.forms:
            return "form"

        return "content"


# ============================================================
# Category-Based Memory
# ============================================================


class CategoryMemory:
    """Store page states by category for efficient retrieval."""

    def __init__(self, max_per_category: int = 10):
        self._memory: dict[str, list[PageState]] = defaultdict(list)
        self._max_per_category = max_per_category

    def store(self, state: PageState):
        """Store a page state in its category."""
        category = state.category
        bucket = self._memory[category]

        # Don't store duplicates (same content hash)
        if any(s.content_hash == state.content_hash for s in bucket):
            return

        bucket.append(state)
        # Evict oldest if over limit
        if len(bucket) > self._max_per_category:
            bucket.pop(0)

    def get(self, category: str) -> list[PageState]:
        """Get all page states for a category."""
        return self._memory.get(category, [])

    def get_categories(self) -> list[str]:
        """Get all stored categories."""
        return list(self._memory.keys())

    def get_summary(self) -> dict:
        """Get memory summary."""
        return {
            category: {
                "count": len(states),
                "urls": [s.url for s in states[:3]],
            }
            for category, states in self._memory.items()
        }

    def to_context_string(self, max_per_category: int = 3) -> str:
        """Format category memory as context for LLM."""
        lines = []
        for category, states in self._memory.items():
            lines.append(f"\n=== {category.upper()} ({len(states)} pages) ===")
            for state in states[:max_per_category]:
                line = f"  {state.url}"
                if state.title:
                    line += f" — {state.title}"
                if state.forms:
                    form_descs = []
                    for f in state.forms:
                        fields = ", ".join(fld.name for fld in f.fields if fld.input_type != "hidden")
                        form_descs.append(f"[{f.method} {f.action}] fields: {fields or 'none'}")
                    line += f"\n    Forms: {'; '.join(form_descs)}"
                if state.headings:
                    line += f"\n    Headings: {', '.join(state.headings[:5])}"
                lines.append(line)
        return "\n".join(lines) if lines else "No categorized page states."


# ============================================================
# Context Engine — Main Orchestrator
# ============================================================


class ContextEngine:
    """
    Main context engineering pipeline.

    Filters ~90% of redundant page states before sending to the LLM.
    Combines DOM extraction, accessibility parsing, network normalization,
    page similarity clustering, and category-based memory.
    """

    def __init__(self):
        self.dom = DOMExtractor()
        self.a11y = AccessibilityTreeParser()
        self.network = NetworkCapture()
        self.clusterer = PageSimilarityClusterer()
        self.memory = CategoryMemory()
        self._raw_context_sizes: list[int] = []
        self._filtered_context_sizes: list[int] = []

    def process_page(self, html: str, url: str) -> PageState:
        """Process a page through the full pipeline."""
        # 1. DOM extraction
        state = self.dom.extract(html, url)

        # 2. Accessibility tree (enrich state)
        a11y_tree = self.a11y.parse(html)
        if not state.headings:
            state.headings = a11y_tree.get("headings", [])
        if not state.landmarks:
            state.landmarks = a11y_tree.get("landmarks", [])

        # 3. Page similarity clustering
        cluster = self.clusterer.add_page(state)

        # 4. Category-based memory
        self.memory.store(state)

        logger.debug(
            f"Processed page: {url} → category={state.category}, "
            f"struct_hash={state.structural_hash}, cluster_size={cluster.count}"
        )
        return state

    def process_request(self, method: str, url: str, status_code: int = 0,
                        response_size: int = 0, content_type: str = ""):
        """Process a network request through normalization."""
        self.network.capture(method, url, status_code, response_size, content_type)

    def build_filtered_context(self, max_network: int = 15,
                                max_categories: int = 5) -> str:
        """Build filtered context for LLM, removing ~90% of redundancy."""
        parts = []

        # Network summary (deduplicated)
        net_summary = self.network.to_context_string(max_entries=max_network)
        if net_summary != "No network requests captured.":
            parts.append(f"=== NETWORK (deduplicated) ===\n{net_summary}")

        # Category memory (representative pages only)
        cat_summary = self.memory.to_context_string(max_per_category=max_categories)
        if cat_summary != "No categorized page states.":
            parts.append(f"=== PAGE STATES (by category) ===\n{cat_summary}")

        # Cluster summary
        cluster_summary = self.clusterer.get_summary()
        if cluster_summary["total_clusters"] > 0:
            parts.append(
                f"=== PAGE CLUSTERS ===\n"
                f"Unique page structures: {cluster_summary['total_clusters']}\n"
                f"Total pages seen: {cluster_summary['total_pages']}\n"
                f"Dedup ratio: {cluster_summary['dedup_ratio']:.0%}\n"
                f"Categories: {json.dumps(cluster_summary['categories'])}"
            )

        filtered = "\n\n".join(parts) if parts else "No context captured yet."

        # Track size metrics
        raw_size = len(json.dumps(self.network.get_raw(limit=100)))
        self._raw_context_sizes.append(raw_size)
        self._filtered_context_sizes.append(len(filtered))

        return filtered

    def get_filter_ratio(self) -> float:
        """Get the average context reduction ratio."""
        if not self._raw_context_sizes:
            return 0.0
        avg_raw = sum(self._raw_context_sizes) / len(self._raw_context_sizes)
        avg_filtered = sum(self._filtered_context_sizes) / len(self._filtered_context_sizes)
        if avg_raw == 0:
            return 0.0
        return round(1 - (avg_filtered / avg_raw), 2)

    def get_metrics(self) -> dict:
        """Get context engineering metrics."""
        return {
            "filter_ratio": self.get_filter_ratio(),
            "network_stats": self.network.get_stats(),
            "cluster_summary": self.clusterer.get_summary(),
            "categories_stored": self.memory.get_categories(),
            "raw_context_sizes": self._raw_context_sizes[-5:],
            "filtered_context_sizes": self._filtered_context_sizes[-5:],
        }

    def get_csrf_tokens(self) -> dict[str, str]:
        """Get all discovered CSRF tokens."""
        tokens = {}
        for state_list in self.memory._memory.values():
            for state in state_list:
                for form in state.forms:
                    if form.csrf_token and form.csrf_field_name:
                        tokens[form.csrf_field_name] = form.csrf_token
        return tokens

    def get_forms_for_url(self, url: str) -> list[ExtractedForm]:
        """Get forms found on a specific URL."""
        for state_list in self.memory._memory.values():
            for state in state_list:
                if state.url == url:
                    return state.forms
        return []

    def get_endpoints(self) -> list[str]:
        """Get all discovered endpoints."""
        return self.network.get_endpoints()

    def to_json(self) -> str:
        """Serialize full context engine state to JSON."""
        return json.dumps({
            "network": self.network.get_stats(),
            "clusters": [c.to_dict() for c in self.clusterer.get_clusters()],
            "categories": self.memory.get_summary(),
            "metrics": self.get_metrics(),
        }, indent=2, default=str)
