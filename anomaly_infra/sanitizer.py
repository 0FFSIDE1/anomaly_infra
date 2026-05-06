SENSITIVE_KEYS = {
    "password",
    "token",
    "refresh",
    "access",
    "authorization",
    "secret",
    "api_key",
    "card",
    "cvv",
    "pin",
}


def _mask(value):
    if value is None:
        return value

    text = str(value)

    if len(text) <= 6:
        return "***"

    return f"{text[:2]}***{text[-2:]}"


def mask_sensitive(data):
    if isinstance(data, dict):
        return {
            key: _mask(value) if key.lower() in SENSITIVE_KEYS else mask_sensitive(value)
            for key, value in data.items()
        }

    if isinstance(data, list):
        return [mask_sensitive(item) for item in data]

    return data