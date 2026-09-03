import sys
import unittest
from pathlib import Path


GRAFANA_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GRAFANA_DIR))

from builder import Builder  # noqa: E402
from tabs import config  # noqa: E402


class ConfigSnapshotTabTest(unittest.TestCase):
    def test_firewall_table_preserves_snapshot_entity_records_and_orders_sequence(self):
        builder = Builder()
        config.build(builder)

        panel = next(
            element for element in builder.elements.values()
            if element["spec"]["title"] == "Firewall & NAT Configuration Snapshots"
        )
        self.assertEqual(panel["spec"]["vizConfig"]["group"], "table")
        query = panel["spec"]["data"]["spec"]["queries"][0]["spec"]["query"]["spec"]["expr"]
        self.assertIn('opnsense_source="configstate"', query)
        self.assertIn('opnsense_subsystem="config"', query)
        self.assertIn('| snapshot_family="firewall" | json', query)
        self.assertIn(
            'label_format snapshot_entity="{{.snapshot_id}} / {{.snapshot_entity_id}}"',
            query,
        )
        self.assertIn("last_over_time", query)
        self.assertIn("| unwrap snapshot_seq [$__range]", query)
        self.assertNotIn("count_over_time", query)
        query_spec = panel["spec"]["data"]["spec"]["queries"][0]["spec"]["query"]["spec"]
        self.assertTrue(query_spec["instant"])
        self.assertFalse(query_spec["range"])

        transformations = panel["spec"]["data"]["spec"]["transformations"]
        by_group = {transform["group"]: transform["spec"]["options"] for transform in transformations}
        organize = by_group["organize"]
        self.assertEqual(
            organize["renameByName"]["snapshot_entity"],
            "Snapshot / Entity",
        )
        self.assertEqual(
            panel["spec"]["vizConfig"]["spec"]["options"]["sortBy"],
            [{"displayName": "Total", "desc": False}],
        )

    def test_device_and_posture_views_use_the_closed_configstate_stream_shape(self):
        builder = Builder()
        config.build(builder)
        panels = {
            element["spec"]["title"]: element
            for element in builder.elements.values()
        }

        device_query = panels["Device Inventory Snapshots"]["spec"]["data"]["spec"]["queries"][0]["spec"]["query"]["spec"]["expr"]
        self.assertIn('opnsense_source="configstate"', device_query)
        self.assertIn('snapshot_family="device_inventory"', device_query)
        self.assertIn('label_format device=', device_query)
        self.assertIn('.entity_hostname', device_query)

        posture_query = panels["Security Posture Snapshots"]["spec"]["data"]["spec"]["queries"][0]["spec"]["query"]["spec"]["expr"]
        self.assertIn('opnsense_source="configstate"', posture_query)
        self.assertIn('snapshot_family="security_posture"', posture_query)
