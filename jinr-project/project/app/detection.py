import re
from .config import CURL_HAMMER_IP



# Pattern 1: YisouSpider botnet
RE_YISOU = re.compile(r"YisouSpider", re.I)

def is_yisouspider_botnet(rec: dict) -> bool:
	return (RE_YISOU.search(rec["ua"]) is not None)

# Pattern 2: event-jinr filter fuzzing (regardless of UA)
RE_EVENT_FUZZ = re.compile(
    r"^/events-jinr(-en)?/events(-en)?/\?category="
)

def is_event_fuzz(rec: dict) -> bool:
	return (RE_EVENT_FUZZ.match(rec["path"]) is not None)

# Pattern 3: same as #2, but the *blocked* variant (403 + tiny body)
def is_blocked_event_fuzz(rec: dict) -> bool:
    return (
        rec["status"] == 403
        and rec["size"] == 199
        and RE_EVENT_FUZZ.match(rec["path"]) is not None
    )

# Pattern 4: curl hammer from a specific IP
RE_CURL_UA = re.compile(r"curl/8\.12\.1")
def is_curl_hammer(rec: dict) -> bool:
    return (
        rec["ip"] == CURL_HAMMER_IP
        and (RE_CURL_UA.search(rec["ua"]) or "wp-cron.php" in rec["path"])
    )

# Pattern 5: bingbot search flood
RE_BINGBOT = re.compile(r"bingbot/2\.0", re.I)
RE_SEARCH  = re.compile(r"/en/?\?s=|/\?s=")
def is_bingbot_flood(rec: dict) -> bool:
    return (
        RE_BINGBOT.search(rec["ua"]) is not None
        and RE_SEARCH.search(rec["path"]) is not None
    )

def classify(rec: dict) -> tuple[bool, str | None]:
    """
    Returns (is_attacker, kind).
    Order matters — most specific first.
    """
    if is_yisouspider_botnet(rec):
        return True, "yisouspider"
    if is_blocked_event_fuzz(rec):
        return True, "event_fuzz_blocked"
    if is_event_fuzz(rec):
        return True, "event_fuzz"
    if is_curl_hammer(rec):
        return True, "curl_hammer"
    if is_bingbot_flood(rec):
        return True, "bingbot_flood"
    return False, None
