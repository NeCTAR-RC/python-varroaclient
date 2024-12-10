#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest import mock

from varroaclient.osc.v1 import security_risks
from varroaclient.tests.unit.osc import base


class TestSecurityRisks(base.OSCTestCase):
    def test_list_security_risks(self):
        command = security_risks.ListSecurityRisks(self.app, None)
        parsed_args = mock.Mock()
        parsed_args.all_projects = False
        parsed_args.project = None
        parsed_args.type = None

        self.client.security_risks.list.return_value = []

        columns, data = command.take_action(parsed_args)

        self.assertEqual(
            columns,
            [
                "id",
                "type",
                "time",
                "ipaddress",
                "port",
                'resource_type',
                'resource_id',
            ],
        )
        self.assertEqual(list(data), [])

    def test_list_security_risks_with_type(self):
        command = security_risks.ListSecurityRisks(self.app, None)
        parsed_args = mock.Mock()
        parsed_args.all_projects = False
        parsed_args.project = None
        parsed_args.type = "test_type"

        self.client.security_risks.list.return_value = []

        columns, data = command.take_action(parsed_args)

        self.assertEqual(
            columns,
            [
                "id",
                "type",
                "time",
                "ipaddress",
                "port",
                'resource_type',
                'resource_id',
            ],
        )
        self.assertEqual(list(data), [])

    def test_show_security_risk(self):
        command = security_risks.ShowSecurityRisk(self.app, None)
        parsed_args = mock.Mock()
        parsed_args.id = "123"

        security_risk = mock.Mock()
        security_risk.to_dict.return_value = {"id": "123", "type": "test"}

        self.client.security_risks.get.return_value = security_risk

        columns, data = command.take_action(parsed_args)

        self.assertIn("id", columns)
        self.assertIn("type", columns)
        self.assertIn("123", data)
        self.assertIn("test", data)

    def test_create_security_risk(self):
        security_risks.CreateSecurityRisk(self.app, None)
        parsed_args = mock.Mock()
        parsed_args.type = "test_type"
        parsed_args.time = "2023-01-01T00:00:00+0000"
        parsed_args.expires = "2023-01-02T00:00:00+0000"
        parsed_args.ipaddress = "192.168.0.1"
        parsed_args.port = 8080

        security_risk_type = mock.Mock()
        security_risk_type.id = "type_id"
        self.client.security_risk_types.find.return_value = security_risk_type

        security_risk = mock.Mock()
        security_risk.to_dict.return_value = {"id": "123", "type": "test_type"}

    def test_delete_security_risk(self):
        command = security_risks.DeleteSecurityRisk(self.app, None)
        parsed_args = mock.Mock()
        parsed_args.id = "123"

        command.take_action(parsed_args)

        self.client.security_risks.delete.assert_called_with("123")
