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

import json

from nectarclient_lib.tests.unit import utils

from varroaclient.tests.unit.v1 import fakes
from varroaclient.v1 import security_risk_types


class SecurityRiskTypesTest(utils.TestCase):

    def setUp(self):
        super().setUp()
        self.cs = fakes.FakeClient()

    def test_security_risk_types_list(self):
        srt_list = self.cs.security_risk_types.list()
        self.cs.assert_called('GET', '/v1/security-risk-types/')
        for srt in srt_list:
            self.assertIsInstance(srt, security_risk_types.SecurityRiskType)
        self.assertEqual(2, len(srt_list))

    def test_security_risk_types_get(self):
        srt = self.cs.security_risk_types.get('type-id')
        self.cs.assert_called('GET', '/v1/security-risk-types/type-id/')
        self.assertIsInstance(srt, security_risk_types.SecurityRiskType)

    def test_security_risk_types_delete(self):
        self.cs.security_risk_types.delete('type-id')
        self.cs.assert_called('DELETE', '/v1/security-risk-types/type-id/')

    def test_security_risk_types_create(self):
        data = {
            'name': 'Test Risk Type',
            'description': 'This is a test risk type'
        }
        srt = self.cs.security_risk_types.create(**data)
        json_data = json.dumps(data)
        self.cs.assert_called('POST', '/v1/security-risk-types/',
                              data=json_data)
        self.assertIsInstance(srt, security_risk_types.SecurityRiskType)

    def test_security_risk_types_update(self):
        data = {
            'name': 'Updated Risk Type',
            'description': 'This is an updated risk type'
        }
        srt = self.cs.security_risk_types.update('type-id', **data)
        json_data = json.dumps(data)
        self.cs.assert_called('PATCH', '/v1/security-risk-types/type-id/',
                              data=json_data)
        self.assertIsInstance(srt, security_risk_types.SecurityRiskType)
