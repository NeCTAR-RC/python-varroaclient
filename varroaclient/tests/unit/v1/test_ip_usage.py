#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.
#

from nectarclient_lib.tests.unit import utils

from varroaclient.tests.unit.v1 import fakes
from varroaclient.v1 import ip_usage


class IPUsageTest(utils.TestCase):
    def setUp(self):
        super().setUp()
        self.cs = fakes.FakeClient()

    def test_ip_usage_list(self):
        ul = self.cs.ip_usage.list()
        self.cs.assert_called("GET", "/v1/ip-usage/")
        for u in ul:
            self.assertIsInstance(u, ip_usage.IPUsage)
        self.assertEqual(1, len(ul))
