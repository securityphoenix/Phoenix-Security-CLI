"""Output rendering for the CLI: json (default for scripting), table, csv."""

import csv
import io
import json

FORMATS = ("table", "json", "csv")
MAX_CELL = 60


def render(data, fmt="table", columns=None):
    """Render API output. Lists of dicts become tables/CSV; everything else
    falls back to pretty JSON."""
    if fmt == "json":
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)
    rows = _normalize_rows(data)
    if rows is None:
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)
    if columns:
        rows = [{c: row.get(c, "") for c in columns} for row in rows]
    if fmt == "csv":
        return _csv(rows)
    return _table(rows)


def _normalize_rows(data):
    if isinstance(data, dict):
        return None
    if isinstance(data, list) and data and all(isinstance(x, dict) for x in data):
        return [_flatten(x) for x in data]
    return None


def _flatten(item):
    out = {}
    for key, value in item.items():
        if isinstance(value, (dict, list)):
            text = json.dumps(value, ensure_ascii=False, default=str)
        else:
            text = "" if value is None else str(value)
        out[key] = text
    return out


def _table(rows):
    if not rows:
        return "(no results)"
    headers = list(rows[0].keys())
    widths = {h: len(h) for h in headers}
    display = []
    for row in rows:
        d = {}
        for h in headers:
            cell = row.get(h, "")
            if len(cell) > MAX_CELL:
                cell = cell[:MAX_CELL - 1] + "…"
            d[h] = cell
            widths[h] = max(widths[h], len(cell))
        display.append(d)
    sep = "  "
    lines = [sep.join(h.ljust(widths[h]) for h in headers),
             sep.join("-" * widths[h] for h in headers)]
    for d in display:
        lines.append(sep.join(d[h].ljust(widths[h]) for h in headers))
    lines.append(f"\n{len(rows)} row(s)")
    return "\n".join(lines)


def _csv(rows):
    if not rows:
        return ""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue().rstrip("\n")
