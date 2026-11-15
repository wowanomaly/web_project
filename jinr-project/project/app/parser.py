import re
from datetime import datetime

# Apache combined log format
LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

TS_FMT = "%d/%b/%Y:%H:%M:%S %z"

def parse_line(line: str) -> dict | None:
    m = LOG_RE.match(line.strip())
    if not m:
        return None
    g = m.groupdict()
    try:
        ts = datetime.strptime(g["ts"], TS_FMT)
    except ValueError:
        return None
    status = int(g["status"]) if g["status"].isdigit() else 0
    size = int(g["size"]) if g["size"].isdigit() else 0
    return {
        "ip": g["ip"],
        "ts": ts,
        "method": g["method"],
        "path": g["path"],
        "status": status,
        "size": size,
        "referer": g["referer"],
        "ua": g["ua"],
    }

def parse_file(path: str):
    with open(path, "r", errors="replace") as f:
        for line in f:
            rec = parse_line(line)
            if rec:
                yield rec
