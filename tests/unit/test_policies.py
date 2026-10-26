"""Tests for the golden-path Checkov policies in policy/checkov/custom.

Each case becomes a resource in a Terraform plan file, and the real Checkov runs
once over all of them. The tests then check that every policy passes and fails
exactly the resources it should. Skipped when Checkov isn't installed
(set GOLD_CHECKOV or put checkov on PATH).
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from collections import namedtuple

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
CUSTOM = os.path.abspath(os.path.join(HERE, "..", "..", "policy", "checkov", "custom"))
CHECKOV = os.environ.get("GOLD_CHECKOV") or shutil.which("checkov")
POLICY_IDS = [f"CKV2_GP_{n}" for n in range(1, 10)]

Case = namedtuple("Case", "policy name rtype values expect")
STD = {"owner": "team-a", "env": "dev", "lifecycle": "persistent", "golden_path": "single-api"}


def provider_of(rtype):
    return {"aws": "aws", "azurerm": "azurerm", "google": "google"}[rtype.split("_")[0]]


def policy_types(filename, index=0):
    """Resource types a YAML policy lists in one of its conditions."""
    with open(os.path.join(CUSTOM, filename)) as fh:
        doc = yaml.safe_load(fh)
    definition = doc["definition"]
    conds = definition[next(iter(definition))]
    return conds[index]["resource_types"]


def build_plan(cases):
    resources = []
    for c in cases:
        prov = provider_of(c.rtype)
        resources.append({
            "address": f"{c.rtype}.{c.name}", "mode": "managed", "type": c.rtype, "name": c.name,
            "provider_name": f"registry.terraform.io/hashicorp/{prov}", "schema_version": 0,
            "values": c.values, "sensitive_values": {},
        })
    provs = sorted({provider_of(c.rtype) for c in cases})
    return {
        "format_version": "1.2", "terraform_version": "1.9.0",
        "planned_values": {"root_module": {"resources": resources}},
        "resource_changes": [{
            "address": r["address"], "mode": "managed", "type": r["type"], "name": r["name"], "provider_name": r["provider_name"],
            "change": {"actions": ["create"], "before": None, "after": r["values"], "after_unknown": {}, "before_sensitive": False, "after_sensitive": {}},
        } for r in resources],
        "configuration": {
            "provider_config": {p: {"name": p, "full_name": f"registry.terraform.io/hashicorp/{p}"} for p in provs},
            "root_module": {"resources": [{
                "address": r["address"], "mode": "managed", "type": r["type"], "name": r["name"],
                "provider_config_key": r["provider_name"].split("/")[-1], "expressions": {}, "schema_version": 0,
            } for r in resources]},
        },
    }


def sg(role, *rules):
    return {"name": "sg", "tags": {**STD, "gp_role": role}, "ingress": [
        {"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": [], "ipv6_cidr_blocks": [], "prefix_list_ids": [], "security_groups": [], "self": False, **r}
        for r in rules]}


def route_table(role, *routes):
    return {"vpc_id": "vpc-1", "tags": {**STD, "gp_role": role}, "route": [
        {"cidr_block": "", "ipv6_cidr_block": "", "gateway_id": "", "nat_gateway_id": "", "carrier_gateway_id": "", "egress_only_gateway_id": "",
         "vpc_peering_connection_id": "", "transit_gateway_id": "", **r} for r in routes]}


def hand_written_cases():
    P, F = "pass", "fail"
    c = []
    # GP_1: prod databases have deletion protection
    c += [
        Case("CKV2_GP_1", "gp1_prod_unprotected", "aws_db_instance", {"identifier": "a", "deletion_protection": False, "tags": {**STD, "env": "prod"}}, F),
        Case("CKV2_GP_1", "gp1_prod_protected", "aws_db_instance", {"identifier": "b", "deletion_protection": True, "tags": {**STD, "env": "prod"}}, P),
        Case("CKV2_GP_1", "gp1_dev_unprotected", "aws_db_instance", {"identifier": "c", "deletion_protection": False, "tags": {**STD, "env": "dev"}}, P),
        Case("CKV2_GP_1", "gp1_untagged", "aws_db_instance", {"identifier": "d", "deletion_protection": False}, P),
        Case("CKV2_GP_1", "gp1_cluster_prod_unprotected", "aws_rds_cluster", {"cluster_identifier": "e", "deletion_protection": False, "tags": {**STD, "env": "prod"}}, F),
        Case("CKV2_GP_1", "gp1_cluster_prod_protected", "aws_rds_cluster", {"cluster_identifier": "f", "deletion_protection": True, "tags": {**STD, "env": "prod"}}, P),
    ]
    # GP_2 and GP_3: ephemeral resources carry expires_at
    exp = "2026-11-01T00:00:00Z"
    for rtype, vals in (("aws_s3_bucket", {"bucket": "b"}), ("azurerm_storage_account", {"name": "sa"})):
        short = rtype.split("_")[0]
        c += [
            Case("CKV2_GP_2", f"gp2_{short}_ephemeral_no_expiry", rtype, {**vals, "tags": {**STD, "lifecycle": "ephemeral"}}, F),
            Case("CKV2_GP_2", f"gp2_{short}_ephemeral_expiry", rtype, {**vals, "tags": {**STD, "lifecycle": "ephemeral", "expires_at": exp}}, P),
            Case("CKV2_GP_2", f"gp2_{short}_persistent", rtype, {**vals, "tags": STD}, P),
            Case("CKV2_GP_2", f"gp2_{short}_untagged", rtype, vals, P),
        ]
    gcp = {"name": "bucket", "location": "US"}
    c += [
        Case("CKV2_GP_3", "gp3_ephemeral_no_expiry", "google_storage_bucket", {**gcp, "labels": {**STD, "lifecycle": "ephemeral"}}, F),
        Case("CKV2_GP_3", "gp3_ephemeral_expiry", "google_storage_bucket", {**gcp, "labels": {**STD, "lifecycle": "ephemeral", "expires_at": "20261101t000000z"}}, P),
        Case("CKV2_GP_3", "gp3_persistent", "google_storage_bucket", {**gcp, "labels": STD}, P),
        Case("CKV2_GP_3", "gp3_unlabelled", "google_storage_bucket", gcp, P),
    ]
    # GP_4 and GP_5: standard tags and labels, one missing key at a time
    for key in STD:
        c.append(Case("CKV2_GP_4", f"gp4_aws_missing_{key}", "aws_s3_bucket", {"bucket": "m", "tags": {k: v for k, v in STD.items() if k != key}}, F))
        c.append(Case("CKV2_GP_4", f"gp4_azure_missing_{key}", "azurerm_key_vault", {"name": "kv", "tags": {k: v for k, v in STD.items() if k != key}}, F))
        c.append(Case("CKV2_GP_5", f"gp5_missing_{key}", "google_storage_bucket", {**gcp, "labels": {k: v for k, v in STD.items() if k != key}}, F))
    c += [
        Case("CKV2_GP_4", "gp4_aws_complete", "aws_s3_bucket", {"bucket": "ok", "tags": STD}, P),
        Case("CKV2_GP_4", "gp4_aws_no_tags", "aws_s3_bucket", {"bucket": "none"}, F),
        Case("CKV2_GP_4", "gp4_azure_complete", "azurerm_key_vault", {"name": "ok", "tags": STD}, P),
        Case("CKV2_GP_5", "gp5_complete", "google_storage_bucket", {**gcp, "labels": STD}, P),
        Case("CKV2_GP_5", "gp5_no_labels", "google_storage_bucket", gcp, F),
    ]
    # GP_6: the app load balancer accepts traffic only from the CDN prefix list
    cdn = {"prefix_list_ids": ["pl-0cdn"]}
    c += [
        Case("CKV2_GP_6", "gp6_cdn_only", "aws_security_group", sg("app-lb", cdn), P),
        Case("CKV2_GP_6", "gp6_no_rules", "aws_security_group", sg("app-lb"), P),
        Case("CKV2_GP_6", "gp6_open_ipv4", "aws_security_group", sg("app-lb", {"cidr_blocks": ["0.0.0.0/0"]}), F),
        Case("CKV2_GP_6", "gp6_private_cidr_no_prefix", "aws_security_group", sg("app-lb", {"cidr_blocks": ["10.0.0.0/8"]}), F),
        Case("CKV2_GP_6", "gp6_open_ipv6", "aws_security_group", sg("app-lb", {"ipv6_cidr_blocks": ["::/0"]}), F),
        Case("CKV2_GP_6", "gp6_from_other_group", "aws_security_group", sg("app-lb", {"security_groups": ["sg-123"]}), F),
        Case("CKV2_GP_6", "gp6_from_self", "aws_security_group", sg("app-lb", {"self": True}), F),
        Case("CKV2_GP_6", "gp6_prefix_and_cidr", "aws_security_group", sg("app-lb", {**cdn, "cidr_blocks": ["10.0.0.0/8"]}), F),
        Case("CKV2_GP_6", "gp6_one_good_one_open", "aws_security_group", sg("app-lb", cdn, {"cidr_blocks": ["0.0.0.0/0"]}), F),
        Case("CKV2_GP_6", "gp6_two_good_rules", "aws_security_group", sg("app-lb", cdn, {**cdn, "from_port": 80, "to_port": 80}), P),
        Case("CKV2_GP_6", "gp6_other_role_open", "aws_security_group", sg("data", {"cidr_blocks": ["0.0.0.0/0"]}), P),
    ]
    # GP_7: the data route table has no internet or NAT route
    c += [
        Case("CKV2_GP_7", "gp7_no_routes", "aws_route_table", route_table("data"), P),
        Case("CKV2_GP_7", "gp7_peering_and_transit", "aws_route_table", route_table("data", {"cidr_block": "10.1.0.0/16", "vpc_peering_connection_id": "pcx-1"}, {"cidr_block": "10.2.0.0/16", "transit_gateway_id": "tgw-1"}), P),
        Case("CKV2_GP_7", "gp7_internet_gateway", "aws_route_table", route_table("data", {"cidr_block": "10.9.0.0/16", "gateway_id": "igw-1"}), F),
        Case("CKV2_GP_7", "gp7_nat_gateway", "aws_route_table", route_table("data", {"cidr_block": "10.9.0.0/16", "nat_gateway_id": "nat-1"}), F),
        Case("CKV2_GP_7", "gp7_default_ipv4", "aws_route_table", route_table("data", {"cidr_block": "0.0.0.0/0", "transit_gateway_id": "tgw-1"}), F),
        Case("CKV2_GP_7", "gp7_default_ipv6", "aws_route_table", route_table("data", {"ipv6_cidr_block": "::/0", "egress_only_gateway_id": "eigw-1"}), F),
        Case("CKV2_GP_7", "gp7_one_good_one_nat", "aws_route_table", route_table("data", {"cidr_block": "10.1.0.0/16", "vpc_peering_connection_id": "pcx-1"}, {"cidr_block": "10.9.0.0/16", "nat_gateway_id": "nat-1"}), F),
        Case("CKV2_GP_7", "gp7_other_role_internet", "aws_route_table", route_table("app", {"cidr_block": "0.0.0.0/0", "gateway_id": "igw-1"}), P),
    ]
    # GP_8: the app tier on Container Apps is internal
    c += [
        Case("CKV2_GP_8", "gp8_internal", "azurerm_container_app_environment", {"name": "e", "internal_load_balancer_enabled": True, "tags": {**STD, "gp_role": "app"}}, P),
        Case("CKV2_GP_8", "gp8_external", "azurerm_container_app_environment", {"name": "e", "internal_load_balancer_enabled": False, "tags": {**STD, "gp_role": "app"}}, F),
        Case("CKV2_GP_8", "gp8_default_is_external", "azurerm_container_app_environment", {"name": "e", "tags": {**STD, "gp_role": "app"}}, F),
        Case("CKV2_GP_8", "gp8_other_role_external", "azurerm_container_app_environment", {"name": "e", "internal_load_balancer_enabled": False, "tags": {**STD, "gp_role": "web"}}, P),
    ]
    # GP_9: the app tier on Cloud Run accepts traffic only from the load balancer
    run = {"name": "svc", "location": "us-central1"}
    c += [
        Case("CKV2_GP_9", "gp9_lb_only", "google_cloud_run_v2_service", {**run, "ingress": "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER", "labels": {**STD, "gp_role": "app"}}, P),
        Case("CKV2_GP_9", "gp9_all", "google_cloud_run_v2_service", {**run, "ingress": "INGRESS_TRAFFIC_ALL", "labels": {**STD, "gp_role": "app"}}, F),
        Case("CKV2_GP_9", "gp9_internal_only", "google_cloud_run_v2_service", {**run, "ingress": "INGRESS_TRAFFIC_INTERNAL_ONLY", "labels": {**STD, "gp_role": "app"}}, F),
        Case("CKV2_GP_9", "gp9_other_role_all", "google_cloud_run_v2_service", {**run, "ingress": "INGRESS_TRAFFIC_ALL", "labels": {**STD, "gp_role": "web"}}, P),
    ]
    return c


def coverage_cases():
    """Every resource type a tag policy lists is really evaluated by it."""
    c = []
    for rtype in policy_types("gp_4_standard_tags.yaml"):
        c.append(Case("CKV2_GP_4", f"cov4_ok_{rtype}", rtype, {"tags": STD}, "pass"))
        c.append(Case("CKV2_GP_4", f"cov4_bare_{rtype}", rtype, {}, "fail"))
        c.append(Case("CKV2_GP_2", f"cov2_bad_{rtype}", rtype, {"tags": {**STD, "lifecycle": "ephemeral"}}, "fail"))
        c.append(Case("CKV2_GP_2", f"cov2_ok_{rtype}", rtype, {"tags": {**STD, "lifecycle": "ephemeral", "expires_at": "2026-11-01T00:00:00Z"}}, "pass"))
    for rtype in policy_types("gp_5_standard_labels_gcp.yaml"):
        c.append(Case("CKV2_GP_5", f"cov5_ok_{rtype}", rtype, {"labels": STD}, "pass"))
        c.append(Case("CKV2_GP_5", f"cov5_bare_{rtype}", rtype, {}, "fail"))
        c.append(Case("CKV2_GP_3", f"cov3_bad_{rtype}", rtype, {"labels": {**STD, "lifecycle": "ephemeral"}}, "fail"))
        c.append(Case("CKV2_GP_3", f"cov3_ok_{rtype}", rtype, {"labels": {**STD, "lifecycle": "ephemeral", "expires_at": "20261101t000000z"}}, "pass"))
    return c


class PolicyFileTests(unittest.TestCase):
    def test_each_policy_id_is_defined_exactly_once(self):
        ids = []
        for name in sorted(os.listdir(CUSTOM)):
            path = os.path.join(CUSTOM, name)
            if name.endswith((".yaml", ".yml")):
                with open(path) as fh:
                    meta = yaml.safe_load(fh)["metadata"]
                self.assertTrue(meta["name"], name)
                ids.append(meta["id"])
            elif name.endswith(".py") and name != "__init__.py":
                with open(path) as fh:
                    ids += [line.split('"')[1] for line in fh if line.strip().startswith('id="CKV2_GP_')]
        self.assertEqual(sorted(ids), sorted(POLICY_IDS))

    def test_the_folder_is_a_package(self):
        self.assertTrue(os.path.exists(os.path.join(CUSTOM, "__init__.py")), "Checkov imports Python checks only from a package")

    def test_paired_policies_cover_the_same_resource_types(self):
        self.assertEqual(policy_types("gp_2_ephemeral_expiry.yaml"), policy_types("gp_4_standard_tags.yaml"))
        self.assertEqual(policy_types("gp_3_ephemeral_expiry_gcp.yaml"), policy_types("gp_5_standard_labels_gcp.yaml"))

    def test_all_tag_conditions_in_a_policy_use_one_resource_list(self):
        for name in ("gp_2_ephemeral_expiry.yaml", "gp_4_standard_tags.yaml", "gp_3_ephemeral_expiry_gcp.yaml", "gp_5_standard_labels_gcp.yaml"):
            with open(os.path.join(CUSTOM, name)) as fh:
                definition = yaml.safe_load(fh)["definition"]
            lists = {tuple(cond["resource_types"]) for cond in definition[next(iter(definition))]}
            self.assertEqual(len(lists), 1, name)


@unittest.skipUnless(CHECKOV, "checkov is not installed")
class PolicyBehaviourTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = hand_written_cases() + coverage_cases()
        names = [c.name for c in cls.cases]
        assert len(names) == len(set(names)), "case names must be unique"
        cls.tmp = tempfile.mkdtemp()
        plan = os.path.join(cls.tmp, "plan.json")
        with open(plan, "w") as fh:
            json.dump(build_plan(cls.cases), fh)
        proc = subprocess.run(
            [CHECKOV, "-f", plan, "--framework", "terraform_plan", "--external-checks-dir", CUSTOM,
             "--check", ",".join(POLICY_IDS), "--soft-fail", "--skip-download", "-o", "json"],
            capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"checkov failed ({proc.returncode}): {proc.stderr[-600:]}")
        docs = json.loads(proc.stdout)
        cls.results = {}
        for doc in docs if isinstance(docs, list) else [docs]:
            for verdict, key in (("pass", "passed_checks"), ("fail", "failed_checks")):
                for item in (doc.get("results") or {}).get(key) or []:
                    cls.results[(item["check_id"], item["resource"])] = verdict

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_every_case_gets_the_expected_verdict(self):
        for c in self.cases:
            with self.subTest(policy=c.policy, case=c.name):
                got = self.results.get((c.policy, f"{c.rtype}.{c.name}"))
                self.assertEqual(got, c.expect, f"{c.policy} on {c.rtype}.{c.name}")

    def test_all_nine_policies_were_exercised(self):
        exercised = {c.policy for c in self.cases}
        self.assertEqual(exercised, set(POLICY_IDS))
        # and each one produced at least one pass and one fail
        for pid in POLICY_IDS:
            verdicts = {v for (cid, _), v in self.results.items() if cid == pid}
            self.assertEqual(verdicts, {"pass", "fail"}, pid)


if __name__ == "__main__":
    unittest.main()
