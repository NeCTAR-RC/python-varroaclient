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

from datetime import datetime
from datetime import timezone
import json

from freezegun import freeze_time
from nectarclient_lib.tests.unit import utils

from varroaclient.tests.unit.v1 import fakes
from varroaclient.v1 import security_risks


@freeze_time("2024-03-15 12:00:00", tz_offset=0)
class SecurityRisksTest(utils.TestCase):

    def setUp(self):
        super().setUp()
        self.cs = fakes.FakeClient()

    def test_security_risks_list(self):
        sl = self.cs.security_risks.list()
        self.cs.assert_called('GET', '/v1/security-risks/')
        for s in sl:
            self.assertIsInstance(s, security_risks.SecurityRisk)
        self.assertEqual(2, len(sl))

    def test_security_risks_get(self):
        s = self.cs.security_risks.get('risk-id')
        self.cs.assert_called('GET', '/v1/security-risks/risk-id/')
        self.assertIsInstance(s, security_risks.SecurityRisk)

    def test_security_risks_delete(self):
        self.cs.security_risks.delete('risk-id')
        self.cs.assert_called('DELETE', '/v1/security-risks/risk-id/')

    def test_security_risks_create(self):
        data = {
            'time': '2023-04-10T12:00:00Z',
            'expires': '2023-04-11T12:00:00Z',
            'type_id': 'type-id',
            'ipaddress': '192.168.1.1',
            'port': 80
        }
        sr = self.cs.security_risks.create(**data)
        json_data = json.dumps(data)
        self.cs.assert_called('POST', '/v1/security-risks/', data=json_data)
        self.assertIsInstance(sr, security_risks.SecurityRisk)

    def test_security_risk_to_dict(self):
        # Create a security risk object
        risk_data = {
            'id': '27b856fb-fc35-43b6-a539-704fc6fb19ad',
            'status': 'PROCESSED',
            'time': '2024-09-16T15:20:45+00:00',
            'ipaddress': '203.0.113.1',
            'port': None,
            'expires': '2024-09-20T23:46:45+00:00',
            'project_id': '094ae1d2c08f4eddb434a9d9db71ab40',
            'resource_id': '218d88fc-df13-445f-b57a-687b3d84fca5',
            'resource_type': 'instance',
            'type': {
                'id': '64471818-c829-4839-8aa7-8393fa050438',
                'name': 'db-exposed',
                'description': 'Database service exposed to the Internet'
            }
        }
        sr = security_risks.SecurityRisk(self.cs.security_risks, risk_data)

        # Call to_dict method
        result = sr.to_dict()

        # Assert the result
        self.assertIsInstance(result, dict)
        self.assertEqual(result['id'], '27b856fb-fc35-43b6-a539-704fc6fb19ad')
        self.assertEqual(result['status'], 'PROCESSED')
        self.assertIsInstance(result['time'], datetime)
        self.assertEqual(
            result['time'],
            datetime(2024, 9, 16, 15, 20, 45, tzinfo=timezone.utc))
        self.assertEqual(result['ipaddress'], '203.0.113.1')
        self.assertIsNone(result['port'])
        self.assertIsInstance(result['expires'], datetime)
        self.assertEqual(
            result['expires'],
             datetime(2024, 9, 20, 23, 46, 45, tzinfo=timezone.utc))
        self.assertEqual(result['project_id'],
                         '094ae1d2c08f4eddb434a9d9db71ab40')
        self.assertEqual(result['resource_id'],
                         '218d88fc-df13-445f-b57a-687b3d84fca5')
        self.assertEqual(result['resource_type'], 'instance')
        self.assertEqual(result['type'], 'db-exposed')
