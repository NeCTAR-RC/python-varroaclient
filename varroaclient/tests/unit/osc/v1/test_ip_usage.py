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

from varroaclient.osc.v1 import ip_usage
from varroaclient.tests.unit.osc import base


class TestIPUsage(base.OSCTestCase):
    def test_list_ip_usage(self):
        command = ip_usage.ListIPUsage(self.app, None)
        parsed_args = mock.Mock()
        parsed_args.all_projects = True
        parsed_args.project = None
        parsed_args.ip = "192.168.0.1"

        self.client.ip_usage.list.return_value = []

        columns, data = command.take_action(parsed_args)

        self.assertEqual(
            columns, ["ip", "project_id", "start", "end", "resource_id"]
        )
        self.assertEqual(list(data), [])

    def test_list_ip_usage_with_project(self):
        command = ip_usage.ListIPUsage(self.app, None)
        parsed_args = mock.Mock()
        parsed_args.all_projects = False
        parsed_args.project = "project-id"
        parsed_args.ip = "192.168.0.1"

        project = mock.Mock()
        project.id = "project-id"
        self.app.client_manager.identity.find_project.return_value = project

        self.client.ip_usage.list.return_value = []

        columns, data = command.take_action(parsed_args)

        self.assertEqual(columns, ["ip", "start", "end", "resource_id"])
        self.assertEqual(list(data), [])

    def test_list_ip_usage_no_ip(self):
        command = ip_usage.ListIPUsage(self.app, None)
        parsed_args = mock.Mock()
        parsed_args.all_projects = True
        parsed_args.project = None
        parsed_args.ip = None

        self.client.ip_usage.list.return_value = []

        columns, data = command.take_action(parsed_args)

        self.assertEqual(
            columns, ["ip", "project_id", "start", "end", "resource_id"]
        )
        self.assertEqual(list(data), [])
