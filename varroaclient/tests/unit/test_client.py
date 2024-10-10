#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License. You may
#   obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.
#

from unittest import mock

from nectarclient_lib.tests.unit import utils

from varroaclient import client


class ClientTest(utils.TestCase):
    def setUp(self):
        super().setUp()
        self.mock_import_module = mock.patch(
            'varroaclient.client.importutils.import_module'
        ).start()
        self.addCleanup(mock.patch.stopall)
        self.mock_module = mock.Mock()
        self.mock_import_module.return_value = self.mock_module
        self.mock_client_class = mock.Mock()
        self.mock_module.Client = self.mock_client_class

    def test_client_initialization(self):
        result = client.Client('1', auth='fake_auth')
        self.mock_import_module.assert_called_once_with(
            "varroaclient.v1.client"
        )
        self.mock_client_class.assert_called_once_with(auth='fake_auth')
        self.assertEqual(result, self.mock_client_class.return_value)


class SessionClientTest(utils.TestCase):
    def setUp(self):
        super().setUp()
        self.session_client = client.SessionClient(session=mock.Mock())

    def test_request_success(self):
        with mock.patch.object(
            self.session_client,
            'request',
            return_value=(mock.Mock(status_code=200), {"key": "value"}),
        ) as mock_request:
            url = "http://example.com"
            method = "GET"
            response, json_data = self.session_client.request(url, method)

            mock_request.assert_called_once_with(url, method)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(json_data, {"key": "value"})
