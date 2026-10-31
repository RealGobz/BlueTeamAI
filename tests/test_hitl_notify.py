import unittest
from unittest.mock import patch, MagicMock
from UI.HITL.notify import _sanitize_toast_text, send_toast


class TestHitlNotify(unittest.TestCase):
    def test_sanitize_text(self):
        raw = "Alert: Trojan detected!\r\nEvil command: cmd.exe\t/c calc"
        clean = _sanitize_toast_text(raw, max_len=40)
        self.assertNotIn("\r", clean)
        self.assertNotIn("\n", clean)
        self.assertNotIn("\t", clean)
        self.assertTrue(len(clean) <= 40)
        self.assertTrue(clean.endswith("..."))

    def test_refuse_non_loopback_url(self):
        res = send_toast("Title", "Message", "http://evil.com/phish")
        self.assertFalse(res)

    @patch("winotify.Notification")
    def test_send_toast_success(self, mock_notif_cls):
        mock_instance = MagicMock()
        mock_notif_cls.return_value = mock_instance

        res = send_toast(
            title="Approval Needed: kill_process",
            message="Suspicious process running",
            url="http://127.0.0.1:8765/r/req123?t=tok456"
        )
        self.assertTrue(res)
        mock_notif_cls.assert_called_once()
        mock_instance.show.assert_called_once()

    @patch("winotify.Notification", side_effect=Exception("Windows Notification Center unavailable"))
    def test_send_toast_graceful_failure(self, mock_notif_cls):
        # Should not raise exception
        res = send_toast(
            title="Approval Needed",
            message="Test message",
            url="http://127.0.0.1:8765/r/req123?t=tok456"
        )
        self.assertFalse(res)


if __name__ == "__main__":
    unittest.main()
