import json
from copy import deepcopy
from uuid import UUID

from anomaly_infra.sanitizer import json_safe, mask_sensitive


def test_masks_sensitive_keys_and_substrings_case_insensitive():
    payload = {
        "password": "secret",
        "access_token": "secret",
        "refresh_token": "secret",
        "Authorization": "Bearer secret",
        "csrfmiddlewaretoken": "secret",
        "Set-Cookie": "secret",
        "safe": "ok",
    }
    masked = mask_sensitive(payload)
    for key in payload:
        if key != "safe":
            assert masked[key] == "***"
    assert masked["safe"] == "ok"


def test_masks_nested_dicts_and_lists_without_mutating_original():
    payload = {"outer": {"api_key": "secret"}, "items": [{"sessionid": "secret"}, {"safe": "ok"}]}
    original = deepcopy(payload)
    masked = mask_sensitive(payload)
    assert masked["outer"]["api_key"] == "***"
    assert masked["items"][0]["sessionid"] == "***"
    assert masked["items"][1]["safe"] == "ok"
    assert payload == original


def test_json_safe_reduces_model_like_objects_to_json_values():
    class UserLike:
        pk = UUID("12345678-1234-5678-1234-567812345678")

    payload = {"actor": UserLike(), "items": (UserLike(),), "safe": "ok"}

    converted = json_safe(payload)

    assert converted == {
        "actor": "12345678-1234-5678-1234-567812345678",
        "items": ["12345678-1234-5678-1234-567812345678"],
        "safe": "ok",
    }
    json.dumps(converted)
