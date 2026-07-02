"""Shared helpers for building Phoenix API payloads."""

from phoenix_cli.errors import PhoenixConfigError


def parse_tag(tag):
    """Normalize a tag into the Phoenix {'key','value'} shape.

    Accepts: "key:value" or "key=value" strings, bare "value" strings,
    or already-shaped dicts ('value' required, 'key' optional).
    """
    if isinstance(tag, dict):
        if "value" not in tag or tag["value"] in (None, ""):
            raise PhoenixConfigError(f"Tag {tag!r} is missing required 'value'.")
        out = {"value": str(tag["value"])}
        if tag.get("key"):
            out["key"] = str(tag["key"])
        if tag.get("id"):
            out["id"] = str(tag["id"])
        return out
    text = str(tag).strip()
    for sep in (":", "="):
        if sep in text:
            key, _, value = text.partition(sep)
            key, value = key.strip(), value.strip()
            if not value:
                raise PhoenixConfigError(f"Tag '{text}' has an empty value.")
            return {"key": key, "value": value} if key else {"value": value}
    if not text:
        raise PhoenixConfigError("Empty tag.")
    return {"value": text}


def parse_tags(tags):
    return [parse_tag(t) for t in (tags or [])]


def user_ref(value):
    """Build a user reference ({'id'} or {'email'}) from a string or dict."""
    if isinstance(value, dict):
        if not value.get("id") and not value.get("email"):
            raise PhoenixConfigError(f"User ref {value!r} needs 'id' or 'email'.")
        return {k: v for k, v in value.items() if k in ("id", "email") and v}
    text = str(value).strip()
    if "@" in text:
        return {"email": text}
    return {"id": text}


def name_selector(name=None, entity_id=None, case_sensitive=None):
    """Build an ApplicationSelector/TeamSelector-style object."""
    selector = {}
    if entity_id:
        selector["id"] = entity_id
    if name:
        selector["name"] = name
    if case_sensitive is not None:
        selector["caseSensitive"] = bool(case_sensitive)
    if not selector:
        raise PhoenixConfigError("A name or id is required for the selector.")
    return selector


def drop_none(mapping):
    """Remove None values so optional fields are omitted, not nulled."""
    return {k: v for k, v in mapping.items() if v is not None}
