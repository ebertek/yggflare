"""Live per-zone capacity guard for opted-in internal DNS creation."""

from cloudflare_api import CloudflareError

INTERNAL_CREATES = frozenset({"create_static_dns_a", "create_docker_dns_a"})


def quota_status(client, zone, reserve):
    if type(reserve) is not int or not 0 <= reserve <= 10000:
        raise ValueError("Invalid internal DNS quota reserve")
    result = {"usage": None, "limit": None, "remaining": None, "reserve": reserve}
    try:
        raw = client.dns_usage(zone)
    except CloudflareError:
        return result
    if not isinstance(raw, dict):
        return result
    usage, limit = raw.get("record_usage"), raw.get("record_quota")
    if type(usage) is not int or usage < 0 or type(limit) is not int or limit < 0:
        return result
    return {
        "usage": usage,
        "limit": limit,
        "remaining": max(0, limit - usage),
        "reserve": reserve,
    }


def capacity_sufficient(quota, count):
    if count == 0:
        return True
    if not isinstance(quota, dict):
        return False
    remaining, reserve = quota.get("remaining"), quota.get("reserve")
    return (
        type(remaining) is int
        and type(reserve) is int
        and reserve >= 0
        and remaining >= count + reserve
    )


def print_quota_summary(report):
    quota = report.get("internal_dns_quota")
    if quota is None:
        return
    if quota["limit"] is None:
        print("Internal DNS quota: unavailable; new internal records are blocked")
    else:
        print(
            f"Internal DNS quota: {quota['usage']}/{quota['limit']} used, "
            f"{quota['remaining']} remaining, {quota['reserve']} reserved"
        )
