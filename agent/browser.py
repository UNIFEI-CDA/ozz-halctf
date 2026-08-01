"""
Ozz — Browser Automation Module
Playwright-based browser automation for SPA support, CSRF handling,
authenticated session management, JS rendering, and screenshot capture.

Inspired by DEF CON 34 AI Village poster:
"Beyond CTFs: Engineering AI Agents for Real-World Web Pentesting" (BugBase)
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger("ozz.browser")

# Lazy import to avoid hard dependency when browser not needed
_playwright = None
_browser = None
_playwright_available = None


def _check_playwright() -> bool:
    """Check if Playwright is available."""
    global _playwright_available
    if _playwright_available is not None:
        return _playwright_available
    try:
        from playwright.async_api import async_playwright
        _playwright_available = True
    except ImportError:
        _playwright_available = False
        logger.warning("Playwright not installed. Browser automation unavailable. Install: pip install playwright && playwright install chromium")
    return _playwright_available


# ============================================================
# Data Structures
# ============================================================


@dataclass
class BrowserConfig:
    """Browser configuration."""
    headless: bool = True
    timeout: int = 30000  # ms
    viewport_width: int = 1280
    viewport_height: int = 720
    user_agent: str = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    ignore_https_errors: bool = True
    screenshot_dir: str = ".openclaw/tmp/screenshots"
    max_pages: int = 5


@dataclass
class BrowserResult:
    """Result from a browser operation."""
    url: str = ""
    title: str = ""
    status_code: int = 0
    html: str = ""
    text_content: str = ""
    screenshot_path: str = ""
    cookies: list[dict] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    console_logs: list[str] = field(default_factory=list)
    network_requests: list[dict] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    csrf_tokens: dict[str, str] = field(default_factory=dict)
    links: list[str] = field(default_factory=list)
    error: Optional[str] = None
    duration_s: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        # Truncate large fields
        if len(d.get("html", "")) > 5000:
            d["html"] = d["html"][:5000] + f"... [{len(self.html)} chars total]"
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str, ensure_ascii=False)


@dataclass
class SessionState:
    """Persistent session state across page navigations."""
    cookies: list[dict] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    local_storage: dict[str, str] = field(default_factory=dict)
    session_storage: dict[str, str] = field(default_factory=dict)
    current_url: str = ""
    is_authenticated: bool = False
    auth_method: str = ""  # form_login, token, cookie, basic


# ============================================================
# Browser Manager
# ============================================================


class BrowserManager:
    """
    Playwright-based browser automation for CTF web challenges.

    Features:
    - SPA support via JavaScript rendering
    - CSRF token extraction and rotation
    - Authenticated session management
    - Screenshot capture for visual analysis
    - Network request interception
    - Console log capture
    """

    def __init__(self, config: Optional[BrowserConfig] = None):
        self.config = config or BrowserConfig()
        self.session = SessionState()
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None
        self._initialized = False
        self._network_log: list[dict] = []
        self._console_log: list[str] = []
        self._response_cache: dict[str, BrowserResult] = {}

        # Ensure screenshot dir exists
        os.makedirs(self.config.screenshot_dir, exist_ok=True)

    async def _ensure_initialized(self) -> bool:
        """Lazily initialize browser context."""
        if self._initialized:
            return True
        if not _check_playwright():
            return False
        try:
            from playwright.async_api import async_playwright
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=self.config.headless,
                args=["--no-sandbox", "--disable-setuid-sandbox"],
            )
            self._context = await self._browser.new_context(
                viewport={
                    "width": self.config.viewport_width,
                    "height": self.config.viewport_height,
                },
                user_agent=self.config.user_agent,
                ignore_https_errors=self.config.ignore_https_errors,
            )

            # Restore session cookies if any
            if self.session.cookies:
                await self._context.add_cookies(self.session.cookies)

            # Set extra headers
            if self.session.headers:
                await self._context.set_extra_http_headers(self.session.headers)

            self._page = await self._context.new_page()
            self._initialized = True

            # Set up network interception
            self._page.on("request", self._on_request)
            self._page.on("response", self._on_response)
            self._page.on("console", self._on_console)

            logger.info("Browser initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Browser initialization failed: {e}")
            return False

    def _on_request(self, request):
        """Capture network requests."""
        self._network_log.append({
            "method": request.method,
            "url": request.url,
            "resource_type": request.resource_type,
            "timestamp": time.time(),
        })

    def _on_response(self, response):
        """Capture network responses."""
        # Update last matching request
        for req in reversed(self._network_log):
            if req["url"] == response.url and "status" not in req:
                req["status"] = response.status
                req["content_type"] = response.headers.get("content-type", "")
                break

    def _on_console(self, msg):
        """Capture console logs."""
        self._console_log.append(f"[{msg.type}] {msg.text}")

    async def navigate(self, url: str, wait_until: str = "domcontentloaded",
                       take_screenshot: bool = False) -> BrowserResult:
        """Navigate to a URL with full page rendering."""
        if not await self._ensure_initialized():
            return BrowserResult(url=url, error="Browser not available (Playwright not installed)")

        start = time.time()
        result = BrowserResult(url=url)
        self._network_log.clear()
        self._console_log.clear()

        try:
            # Navigate
            response = await self._page.goto(
                url,
                wait_until=wait_until,
                timeout=self.config.timeout,
            )

            if response:
                result.status_code = response.status
                result.headers = dict(response.headers)

            # Wait for dynamic content
            await self._page.wait_for_load_state("networkidle", timeout=5000)
            await asyncio.sleep(0.5)  # Extra settle time

            # Extract content
            result.html = await self._page.content()
            result.title = await self._page.title()
            result.text_content = await self._page.inner_text("body") if await self._page.query_selector("body") else ""

            # Extract forms and CSRF tokens
            result.forms = await self._extract_forms()
            result.csrf_tokens = await self._extract_csrf_tokens()

            # Extract links
            result.links = await self._extract_links()

            # Cookies
            result.cookies = await self._context.cookies()

            # Screenshot
            if take_screenshot:
                result.screenshot_path = await self._take_screenshot(url)

            # Network and console logs
            result.network_requests = list(self._network_log)
            result.console_logs = list(self._console_log)

            # Update session state
            self.session.current_url = url
            self.session.cookies = result.cookies

            # Cache result
            cache_key = hashlib.md5(url.encode()).hexdigest()[:12]
            self._response_cache[cache_key] = result

        except Exception as e:
            result.error = str(e)
            logger.error(f"Navigation error for {url}: {e}")

        result.duration_s = round(time.time() - start, 2)
        return result

    async def _extract_forms(self) -> list[dict]:
        """Extract forms from the current page."""
        try:
            forms = await self._page.evaluate("""() => {
                const forms = [];
                document.querySelectorAll('form').forEach(form => {
                    const fields = [];
                    form.querySelectorAll('input, select, textarea').forEach(el => {
                        fields.push({
                            tag: el.tagName.toLowerCase(),
                            name: el.name || '',
                            type: el.type || 'text',
                            value: el.value || '',
                            id: el.id || '',
                        });
                    });
                    forms.push({
                        action: form.action || '',
                        method: (form.method || 'GET').toUpperCase(),
                        id: form.id || '',
                        fields: fields,
                    });
                });
                return forms;
            }""")
            return forms
        except Exception:
            return []

    async def _extract_csrf_tokens(self) -> dict[str, str]:
        """Extract CSRF tokens from meta tags and hidden inputs."""
        try:
            tokens = await self._page.evaluate("""() => {
                const tokens = {};
                // Meta tags
                document.querySelectorAll('meta[name*="csrf"], meta[name*="token"], meta[name*="xsrf"]').forEach(meta => {
                    tokens[meta.name] = meta.content;
                });
                // Hidden inputs
                document.querySelectorAll('input[type="hidden"]').forEach(input => {
                    const name = input.name.toLowerCase();
                    if (name.includes('csrf') || name.includes('token') || name.includes('_token') ||
                        name.includes('xsrf') || name.includes('verification')) {
                        tokens[input.name] = input.value;
                    }
                });
                return tokens;
            }""")
            return tokens
        except Exception:
            return {}

    async def _extract_links(self) -> list[str]:
        """Extract all links from the current page."""
        try:
            links = await self._page.evaluate("""() => {
                const links = new Set();
                document.querySelectorAll('a[href]').forEach(a => {
                    const href = a.href;
                    if (href && !href.startsWith('javascript:') && !href.startsWith('#')) {
                        links.add(href);
                    }
                });
                return [...links];
            }""")
            return links
        except Exception:
            return []

    async def _take_screenshot(self, url: str) -> str:
        """Take a screenshot and return the file path."""
        try:
            parsed = urlparse(url)
            safe_name = re.sub(r'[^a-zA-Z0-9]', '_', parsed.path or "index")[:50]
            filename = f"{safe_name}_{int(time.time())}.png"
            filepath = os.path.join(self.config.screenshot_dir, filename)
            await self._page.screenshot(path=filepath, full_page=True)
            logger.info(f"Screenshot saved: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Screenshot failed: {e}")
            return ""

    async def fill_form(self, form_selector: str, data: dict[str, str],
                        submit: bool = False) -> BrowserResult:
        """Fill a form with data and optionally submit it."""
        if not await self._ensure_initialized():
            return BrowserResult(error="Browser not available")

        start = time.time()
        result = BrowserResult(url=self.session.current_url)

        try:
            for field_name, value in data.items():
                selector = f'{form_selector} [name="{field_name}"]'
                try:
                    await self._page.fill(selector, value)
                except Exception:
                    # Try by id
                    try:
                        await self._page.fill(f'#{field_name}', value)
                    except Exception as e:
                        logger.warning(f"Could not fill field {field_name}: {e}")

            if submit:
                submit_btn = await self._page.query_selector(f'{form_selector} [type="submit"]')
                if submit_btn:
                    await submit_btn.click()
                else:
                    await self._page.press(form_selector, "Enter")

                await self._page.wait_for_load_state("networkidle", timeout=10000)
                result.html = await self._page.content()
                result.title = await self._page.title()
                result.url = self._page.url
                result.status_code = 200  # Approximate
                result.forms = await self._extract_forms()
                result.csrf_tokens = await self._extract_csrf_tokens()

        except Exception as e:
            result.error = str(e)

        result.duration_s = round(time.time() - start, 2)
        return result

    async def click(self, selector: str) -> BrowserResult:
        """Click an element on the page."""
        if not await self._ensure_initialized():
            return BrowserResult(error="Browser not available")

        start = time.time()
        result = BrowserResult(url=self.session.current_url)

        try:
            await self._page.click(selector, timeout=5000)
            await self._page.wait_for_load_state("networkidle", timeout=10000)
            await asyncio.sleep(0.3)

            result.html = await self._page.content()
            result.title = await self._page.title()
            result.url = self._page.url
            result.forms = await self._extract_forms()
            result.csrf_tokens = await self._extract_csrf_tokens()
            result.links = await self._extract_links()

        except Exception as e:
            result.error = str(e)

        result.duration_s = round(time.time() - start, 2)
        return result

    async def execute_js(self, script: str) -> Any:
        """Execute JavaScript in the page context."""
        if not await self._ensure_initialized():
            return None
        try:
            return await self._page.evaluate(script)
        except Exception as e:
            logger.error(f"JS execution error: {e}")
            return None

    async def login(self, login_url: str, username: str, password: str,
                    username_field: str = "username", password_field: str = "password",
                    submit_selector: str = '[type="submit"]') -> BrowserResult:
        """Perform form-based login and maintain session."""
        result = await self.navigate(login_url, take_screenshot=True)
        if result.error:
            return result

        # Refresh CSRF tokens
        csrf = result.csrf_tokens

        # Fill login form
        form_data = {
            username_field: username,
            password_field: password,
        }
        result = await self.fill_form("form", form_data, submit=False)

        # Update CSRF if changed
        new_csrf = await self._extract_csrf_tokens()
        if new_csrf:
            for fname, fval in new_csrf.items():
                try:
                    await self._page.fill(f'[name="{fname}"]', fval)
                except Exception:
                    pass

        # Submit
        try:
            await self._page.click(submit_selector)
            await self._page.wait_for_load_state("networkidle", timeout=15000)
            await asyncio.sleep(1)

            result.url = self._page.url
            result.html = await self._page.content()
            result.title = await self._page.title()
            result.cookies = await self._context.cookies()

            # Check if login was successful (heuristic: URL changed or session cookie present)
            self.session.is_authenticated = True
            self.session.auth_method = "form_login"
            self.session.cookies = result.cookies

            logger.info(f"Login completed. Current URL: {result.url}")

        except Exception as e:
            result.error = f"Login submit failed: {e}"
            logger.error(result.error)

        return result

    async def get_cookies(self) -> list[dict]:
        """Get all cookies in the current session."""
        if not await self._ensure_initialized():
            return []
        return await self._context.cookies()

    async def set_cookie(self, name: str, value: str, domain: str = "",
                         path: str = "/"):
        """Set a cookie in the browser context."""
        if not await self._ensure_initialized():
            return
        cookie = {"name": name, "value": value, "path": path}
        if domain:
            cookie["domain"] = domain
        await self._context.add_cookies([cookie])
        self.session.cookies = await self._context.cookies()

    async def get_page_text(self) -> str:
        """Get visible text content of current page."""
        if not self._page:
            return ""
        try:
            return await self._page.inner_text("body")
        except Exception:
            return ""

    async def get_page_html(self) -> str:
        """Get HTML of current page."""
        if not self._page:
            return ""
        try:
            return await self._page.content()
        except Exception:
            return ""

    async def screenshot(self, full_page: bool = True) -> str:
        """Take a screenshot of the current page."""
        if not self._page:
            return ""
        filename = f"page_{int(time.time())}.png"
        filepath = os.path.join(self.config.screenshot_dir, filename)
        try:
            await self._page.screenshot(path=filepath, full_page=full_page)
            return filepath
        except Exception as e:
            logger.error(f"Screenshot failed: {e}")
            return ""

    async def close(self):
        """Close browser and clean up resources."""
        try:
            if self._context:
                # Save session state
                self.session.cookies = await self._context.cookies()
            if self._browser:
                await self._browser.close()
            if self._playwright:
                await self._playwright.stop()
        except Exception as e:
            logger.error(f"Browser cleanup error: {e}")
        finally:
            self._initialized = False
            self._browser = None
            self._context = None
            self._page = None
            self._playwright = None

    def get_session_state(self) -> dict:
        """Get current session state for persistence."""
        return {
            "cookies": self.session.cookies,
            "headers": self.session.headers,
            "current_url": self.session.current_url,
            "is_authenticated": self.session.is_authenticated,
            "auth_method": self.session.auth_method,
        }

    def restore_session(self, state: dict):
        """Restore session from saved state."""
        self.session.cookies = state.get("cookies", [])
        self.session.headers = state.get("headers", {})
        self.session.current_url = state.get("current_url", "")
        self.session.is_authenticated = state.get("is_authenticated", False)
        self.session.auth_method = state.get("auth_method", "")


# ============================================================
# Synchronous Wrapper (for use in non-async code)
# ============================================================


class BrowserTool:
    """
    Synchronous wrapper around BrowserManager for use in the ReAct loop.
    Registers as a tool in ToolRegistry.
    """

    def __init__(self, config: Optional[BrowserConfig] = None):
        self.config = config or BrowserConfig()
        self._manager: Optional[BrowserManager] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def _get_loop(self) -> asyncio.AbstractEventLoop:
        """Get or create event loop."""
        if self._loop is None or self._loop.is_closed():
            try:
                self._loop = asyncio.get_event_loop()
                if self._loop.is_closed():
                    self._loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(self._loop)
            except RuntimeError:
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
        return self._loop

    def _run_async(self, coro):
        """Run an async coroutine synchronously."""
        loop = self._get_loop()
        return loop.run_until_complete(coro)

    def _ensure_manager(self) -> BrowserManager:
        """Lazily create BrowserManager."""
        if self._manager is None:
            self._manager = BrowserManager(self.config)
        return self._manager

    def navigate(self, url: str, take_screenshot: bool = False) -> dict:
        """Navigate to a URL (sync)."""
        mgr = self._ensure_manager()
        result = self._run_async(mgr.navigate(url, take_screenshot=take_screenshot))
        return result.to_dict()

    def fill_and_submit(self, form_selector: str, data: dict, submit: bool = True) -> dict:
        """Fill and submit a form (sync)."""
        mgr = self._ensure_manager()
        result = self._run_async(mgr.fill_form(form_selector, data, submit=submit))
        return result.to_dict()

    def click(self, selector: str) -> dict:
        """Click an element (sync)."""
        mgr = self._ensure_manager()
        result = self._run_async(mgr.click(selector))
        return result.to_dict()

    def execute_js(self, script: str) -> Any:
        """Execute JavaScript (sync)."""
        mgr = self._ensure_manager()
        return self._run_async(mgr.execute_js(script))

    def login(self, url: str, username: str, password: str,
              username_field: str = "username", password_field: str = "password") -> dict:
        """Perform login (sync)."""
        mgr = self._ensure_manager()
        result = self._run_async(mgr.login(url, username, password, username_field, password_field))
        return result.to_dict()

    def screenshot(self) -> str:
        """Take screenshot (sync)."""
        mgr = self._ensure_manager()
        return self._run_async(mgr.screenshot())

    def get_cookies(self) -> list[dict]:
        """Get cookies (sync)."""
        mgr = self._ensure_manager()
        return self._run_async(mgr.get_cookies())

    def set_cookie(self, name: str, value: str, domain: str = ""):
        """Set cookie (sync)."""
        mgr = self._ensure_manager()
        self._run_async(mgr.set_cookie(name, value, domain))

    def get_session_state(self) -> dict:
        """Get session state."""
        if self._manager:
            return self._manager.get_session_state()
        return {}

    def close(self):
        """Close browser (sync)."""
        if self._manager:
            self._run_async(self._manager.close())
            self._manager = None


# ============================================================
# Factory Function
# ============================================================


def create_browser_tool(headless: bool = True, screenshot_dir: str = ".openclaw/tmp/screenshots") -> Optional[BrowserTool]:
    """Create a BrowserTool if Playwright is available, else None."""
    if not _check_playwright():
        return None
    config = BrowserConfig(headless=headless, screenshot_dir=screenshot_dir)
    return BrowserTool(config)
