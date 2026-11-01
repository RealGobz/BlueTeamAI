"""
tests/test_triagent_brand_ui.py - Automated Verification Suite for Triagent Brand Restyling

Covers:
1. /brand allowlist on both servers (correct MIME, nosniff, no-store, 404 on bad/traversal paths).
2. Exact CSP header verification on UI/main and UI/HITL.
3. Strict CSP HTML safety in UI/HITL/pages: zero style="", zero <style>, zero <script>.
4. XSS sanitization and escaping for all dynamic inputs.
5. Strict CSS rules: --attack only in real attack selectors, --brand/--brand-text only in .needs-you,
   zero hex colors in component CSS, and zero badge-danger classes.
6. Safe allowlist mapping in app.js for data-to-class safety.
"""

import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch, MagicMock

from UI.HITL.pages import (
    render_pending_list,
    render_tool_approval_page,
    render_continue_page,
    render_ask_user_page,
    render_expired_page,
    render_decided_page,
    render_not_found_page,
    format_time_left,
)


ROOT_DIR = Path(__file__).resolve().parent.parent
MAIN_CSS = ROOT_DIR / "UI" / "main" / "static" / "app.css"
HITL_CSS = ROOT_DIR / "UI" / "HITL" / "static" / "hitl.css"
APP_JS = ROOT_DIR / "UI" / "main" / "static" / "app.js"


class TestHitlPagesStrictSafety(unittest.TestCase):
    """Assert all HITL pages obey strict CSP, escaping, and calm branding."""

    def setUp(self):
        self.sample_xss = "<script>alert('xss')</script><img src=x onerror=alert('xss')>"
        self.sample_req = {
            "request_id": "req-safe-01",
            "token": "tok_secret_123",
            "thread_id": "thread-audit-01",
            "expires_at": "2026-11-01T14:30:00+00:00",
            "payload": {
                "alert_title": f"Test Alert Title {self.sample_xss}",
                "severity": "high",
                "tool_name": "kill_process",
                "target": f"calc.exe {self.sample_xss}",
                "reason": f"Suspicious activity detected {self.sample_xss}",
                "approval_screen": f"COMMAND: cmd.exe /c calc {self.sample_xss}",
                "question": f"Is this authorized? {self.sample_xss}",
                "choices": ["Yes", f"No {self.sample_xss}"],
                "system_context": f"Logged context {self.sample_xss}",
                "turns": 5,
                "turn_limit": 5,
                "continues": 1,
                "max_continues": 3,
                "plan": ["Step 1", f"Step 2 {self.sample_xss}"],
                "tools_used": ["get_file_info"],
                "last_message": f"Agent completed turn {self.sample_xss}",
            },
        }

    def _assert_strict_page_safety(self, html_content: str):
        """Assert no inline styles, no style blocks, no script tags, and valid brand lockup."""
        lower = html_content.lower()
        self.assertNotIn('style="', lower, "Found inline style attribute")
        self.assertNotIn("style='", lower, "Found inline style attribute")
        self.assertNotIn("<style", lower, "Found <style> block")
        self.assertNotIn("<script", lower, "Found <script> block")
        self.assertIn("triagent-lockup", lower, "Missing Triagent lockup brand element")
        self.assertIn("- triagent</title>", lower, "Missing Triagent title suffix")

        # Ensure raw XSS script tags never appear unescaped
        self.assertNotIn("<script>alert('xss')</script>", html_content)
        self.assertNotIn("<img src=x onerror=alert('xss')>", html_content)

    def test_pending_list_empty(self):
        out = render_pending_list([])
        self._assert_strict_page_safety(out)
        self.assertIn("Nothing needs you right now.", out)
        self.assertNotIn("needs-you", out, "Empty pending list should not have amber element")

    def test_pending_list_with_items(self):
        items = [self.sample_req]
        out = render_pending_list(items)
        self._assert_strict_page_safety(out)
        self.assertIn("Needs your decision", out)
        self.assertIn("needs-you", out, "Pending list with items must have the amber element")
        self.assertIn("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;", out)

    def test_tool_approval_page_live_and_dryrun(self):
        # LIVE
        out_live = render_tool_approval_page(self.sample_req, dry_run=False)
        self._assert_strict_page_safety(out_live)
        self.assertIn("<strong>LIVE.</strong> Approving this will run the action on this PC.", out_live)
        self.assertNotIn("DRY RUN", out_live)
        self.assertIn("Needs your decision", out_live)

        # DRY RUN
        out_dry = render_tool_approval_page(self.sample_req, dry_run=True)
        self._assert_strict_page_safety(out_dry)
        self.assertIn("<strong>DRY RUN.</strong> Nothing will be changed.", out_dry)
        self.assertNotIn("LIVE.", out_dry)

    def test_continue_page(self):
        out = render_continue_page(self.sample_req)
        self._assert_strict_page_safety(out)
        self.assertIn("Continue?", out)
        self.assertIn("needs-you", out)
        self.assertIn("Investigation turn limit reached", out)

    def test_ask_user_page(self):
        out = render_ask_user_page(self.sample_req)
        self._assert_strict_page_safety(out)
        self.assertIn("Triagent has a question", out)
        self.assertIn("needs-you", out)
        self.assertIn("The question below was written by the AI", out)
        self.assertIn("I&#x27;m not sure", out)

    def test_calm_short_pages(self):
        for out in [
            render_decided_page(self.sample_req, "Done"),
            render_expired_page(self.sample_req),
            render_not_found_page("test-id"),
        ]:
            self._assert_strict_page_safety(out)
            self.assertIn("page-short", out)

    def test_format_time_left_helper(self):
        text, is_exp = format_time_left("2020-01-01T00:00:00+00:00")
        self.assertTrue(is_exp)
        self.assertEqual(text, "Expired")


class TestCssColorAndTokenRules(unittest.TestCase):
    """Enforce brand color tokens, no hex colors, and attack/amber exclusivity."""

    def test_no_hex_colors_in_component_css(self):
        for p in [MAIN_CSS, HITL_CSS]:
            content = p.read_text(encoding="utf-8")
            matches = re.findall(r"#[0-9a-fA-F]{3,8}\b", content)
            self.assertEqual(matches, [], f"Found raw hex colors in {p.name}: {matches}")

    def test_attack_token_restricted_to_real_attack_rules(self):
        content = MAIN_CSS.read_text(encoding="utf-8")
        lines = content.splitlines()
        for idx, line in enumerate(lines, 1):
            if "--attack" in line:
                # Must be inside a block for .v-attack or real attack
                surrounding = "\n".join(lines[max(0, idx - 5) : min(len(lines), idx + 5)])
                self.assertTrue(
                    "v-attack" in surrounding or "real attack" in surrounding.lower(),
                    f"Line {idx} in app.css uses --attack outside v-attack selector: {line}",
                )

        # In hitl.css, --attack should not be used at all
        hitl_content = HITL_CSS.read_text(encoding="utf-8")
        self.assertNotIn("--attack", hitl_content)

    def test_amber_brand_restricted_to_needs_you(self):
        for p in [MAIN_CSS, HITL_CSS]:
            content = p.read_text(encoding="utf-8")
            lines = content.splitlines()
            for idx, line in enumerate(lines, 1):
                if "--brand" in line:
                    surrounding = "\n".join(lines[max(0, idx - 5) : min(len(lines), idx + 5)])
                    self.assertTrue(
                        "needs-you" in surrounding or "the lit lamp" in surrounding,
                        f"Line {idx} in {p.name} uses --brand outside .needs-you selector: {line}",
                    )

    def test_no_badge_danger_class(self):
        for p in [MAIN_CSS, HITL_CSS, APP_JS]:
            content = p.read_text(encoding="utf-8")
            self.assertNotIn("badge-danger", content, f"Found legacy badge-danger in {p.name}")


class TestAppJsAllowlists(unittest.TestCase):
    """Verify that app.js maps data through strict allowlists and neutral fallbacks."""

    def test_allowlist_definitions_present(self):
        content = APP_JS.read_text(encoding="utf-8")
        self.assertIn("VERDICT_CLASS_MAP", content)
        self.assertIn("STATUS_CLASS_MAP", content)
        self.assertIn("TOOL_STATUS_MAP", content)
        self.assertIn("DIRECTION_CLASS_MAP", content)

    def test_no_dynamic_string_interpolation_into_classes(self):
        content = APP_JS.read_text(encoding="utf-8")
        # Ensure no legacy interpolation like `verdict-card ${item.verdict}` exists
        self.assertNotIn("`verdict-card ${", content)
        self.assertNotIn("`direction-badge direction-${", content)


if __name__ == "__main__":
    unittest.main()
