"""CKV2_GP_7: three-tier data route tables have no internet or NAT route.

A route table tagged gp_role = data may not route to an internet, NAT, carrier
or egress-only gateway, and may not carry a default route. Only inline routes
are covered; use them for this tier.
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

GATEWAY_KEYS = ("gateway_id", "nat_gateway_id", "carrier_gateway_id", "egress_only_gateway_id")
DEFAULT_ROUTES = {"0.0.0.0/0", "::/0"}


def flat(value):
    """Yield the non-empty scalars in a value that may be nested in lists."""
    if isinstance(value, (list, tuple)):
        for item in value:
            yield from flat(item)
    elif value not in (None, "", False):
        yield value


def tag(conf, key):
    tags = conf.get("tags")
    if isinstance(tags, list) and tags:
        tags = tags[0]
    value = tags.get(key) if isinstance(tags, dict) else None
    return value[0] if isinstance(value, list) and value else value


class DataRoutesPrivate(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Three-tier data route tables have no internet or NAT route",
            id="CKV2_GP_7",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["aws_route_table"],
        )

    def scan_resource_conf(self, conf):
        if tag(conf, "gp_role") != "data":
            return CheckResult.PASSED
        for route in conf.get("route") or []:
            if not isinstance(route, dict):
                continue
            if any(list(flat(route.get(key))) for key in GATEWAY_KEYS):
                return CheckResult.FAILED
            destinations = [*flat(route.get("cidr_block")), *flat(route.get("ipv6_cidr_block"))]
            if DEFAULT_ROUTES.intersection(destinations):
                return CheckResult.FAILED
        return CheckResult.PASSED


check = DataRoutesPrivate()
