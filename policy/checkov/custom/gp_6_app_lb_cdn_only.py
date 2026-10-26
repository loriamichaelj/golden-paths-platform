"""CKV2_GP_6: the three-tier app load balancer accepts traffic only from the CDN.

A security group tagged gp_role = app-lb may only allow ingress from a managed
prefix list (the CDN's). Every rule is checked, so one open rule fails the group.
Only inline ingress rules are covered; use them for this tier.
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


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


class AppLoadBalancerOnlyFromCdn(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Three-tier app load balancer accepts traffic only from the CDN prefix list",
            id="CKV2_GP_6",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["aws_security_group"],
        )

    def scan_resource_conf(self, conf):
        if tag(conf, "gp_role") != "app-lb":
            return CheckResult.PASSED
        for rule in conf.get("ingress") or []:
            if not isinstance(rule, dict):
                continue
            other_sources = [
                *flat(rule.get("cidr_blocks")),
                *flat(rule.get("ipv6_cidr_blocks")),
                *flat(rule.get("security_groups")),
                *flat(rule.get("self")),
            ]
            if other_sources or not list(flat(rule.get("prefix_list_ids"))):
                return CheckResult.FAILED
        return CheckResult.PASSED


check = AppLoadBalancerOnlyFromCdn()
