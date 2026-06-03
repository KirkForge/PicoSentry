"""Tests for picodome.errors — structured error codes."""

from picosentry.sandbox.errors import ErrorCode, ErrorCodes


class TestErrorCode:
    """Tests for ErrorCode dataclass."""

    def test_error_code_fields(self):
        code = ErrorCodes.INVALID_JSON
        assert code.status == 400
        assert code.key == "INVALID_JSON"
        assert code.message == "Invalid JSON body"

    def test_error_code_is_frozen(self):
        code = ErrorCodes.UNAUTHORIZED
        # Frozen dataclass should not allow attribute assignment
        try:
            code.status = 500
            raise AssertionError("Should have raised FrozenInstanceError")
        except AttributeError:
            pass

    def test_all_error_codes_have_valid_status(self):
        """Every error code should have a valid HTTP status."""
        for attr in dir(ErrorCodes):
            if attr.startswith("_"):
                continue
            code = getattr(ErrorCodes, attr)
            if isinstance(code, ErrorCode):
                assert 400 <= code.status <= 599, f"{attr}: status {code.status} not in 4xx-5xx range"
                assert len(code.key) > 0, f"{attr}: empty key"
                assert len(code.message) > 0, f"{attr}: empty message"


class TestErrorCodesRegistry:
    """Tests for the ErrorCodes registry."""

    def test_400_codes(self):
        assert ErrorCodes.INVALID_JSON.status == 400
        assert ErrorCodes.MISSING_COMMAND.status == 400
        assert ErrorCodes.INVALID_BACKEND.status == 400
        assert ErrorCodes.INVALID_POLICY.status == 400

    def test_401_codes(self):
        assert ErrorCodes.UNAUTHORIZED.status == 401

    def test_403_codes(self):
        assert ErrorCodes.FORBIDDEN.status == 403
        assert ErrorCodes.COMMAND_DENIED.status == 403
        assert ErrorCodes.ENTERPRISE_ENFORCEMENT.status == 403

    def test_404_codes(self):
        assert ErrorCodes.NOT_FOUND.status == 404
        assert ErrorCodes.SCAN_NOT_FOUND.status == 404
        assert ErrorCodes.POLICY_NOT_FOUND.status == 404

    def test_413_codes(self):
        assert ErrorCodes.REQUEST_TOO_LARGE.status == 413

    def test_429_codes(self):
        assert ErrorCodes.RATE_LIMITED.status == 429

    def test_500_codes(self):
        assert ErrorCodes.SCAN_FAILED.status == 500
        assert ErrorCodes.INTERNAL_ERROR.status == 500

    def test_503_codes(self):
        assert ErrorCodes.NOT_READY.status == 503
        assert ErrorCodes.BACKEND_UNAVAILABLE.status == 503

    def test_error_code_keys_are_unique(self):
        """All error code keys should be unique."""
        keys = set()
        for attr in dir(ErrorCodes):
            if attr.startswith("_"):
                continue
            code = getattr(ErrorCodes, attr)
            if isinstance(code, ErrorCode):
                assert code.key not in keys, f"Duplicate key: {code.key}"
                keys.add(code.key)