#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest import mock

from varroaclient.osc.v1 import security_risk_types
from varroaclient.tests.unit.osc import base


class TestSecurityRiskTypes(base.OSCTestCase):
    def test_list_security_risk_types(self):
        command = security_risk_types.ListSecurityRiskTypes(self.app, None)
        parsed_args = mock.Mock()

        self.client.security_risk_types.list.return_value = []

        columns, data = command.take_action(parsed_args)

        self.assertEqual(columns, ["id", "name", "description"])
        self.assertEqual(list(data), [])

    def test_show_security_risk_type(self):
        command = security_risk_types.ShowSecurityRiskType(self.app, None)
        parsed_args = mock.Mock()
        parsed_args.id = "type-id"

        security_risk_type = mock.Mock()
        security_risk_type.to_dict.return_value = {
            "id": "type-id",
            "name": "test",
        }

        self.client.security_risk_types.get.return_value = security_risk_type

        columns, data = command.take_action(parsed_args)

        self.assertIn("id", columns)
        self.assertIn("name", columns)
        self.assertIn("type-id", data)
        self.assertIn("test", data)

    def test_create_security_risk_type(self):
        command = security_risk_types.CreateSecurityRiskType(self.app, None)
        parsed_args = mock.Mock()
        parsed_args.name = "test_name"
        parsed_args.description = "test_description"

        security_risk_type = mock.Mock()
        security_risk_type.to_dict.return_value = {
            "id": "type-id",
            "name": "test_name",
        }

        self.client.security_risk_types.create.return_value = (
            security_risk_type
        )

        columns, data = command.take_action(parsed_args)

        self.assertIn("id", columns)
        self.assertIn("name", columns)
        self.assertIn("type-id", data)
        self.assertIn("test_name", data)

    def test_update_security_risk_type(self):
        command = security_risk_types.UpdateSecurityRiskType(self.app, None)
        parsed_args = mock.Mock()
        parsed_args.id = "type-id"
        parsed_args.name = "updated_name"
        parsed_args.description = "updated_description"

        security_risk_type = mock.Mock()
        security_risk_type.to_dict.return_value = {
            "id": "type-id",
            "name": "updated_name",
        }

        self.client.security_risk_types.update.return_value = (
            security_risk_type
        )

        columns, data = command.take_action(parsed_args)

        self.assertIn("id", columns)
        self.assertIn("name", columns)
        self.assertIn("type-id", data)
        self.assertIn("updated_name", data)

    def test_delete_security_risk_type(self):
        command = security_risk_types.DeleteSecurityRiskType(self.app, None)
        parsed_args = mock.Mock()
        parsed_args.id = "type-id"
        srt = mock.Mock()
        srt.id = "type-id"
        self.client.security_risk_types.get.return_value = srt

        command.take_action(parsed_args)

        self.client.security_risk_types.delete.assert_called_with("type-id")
