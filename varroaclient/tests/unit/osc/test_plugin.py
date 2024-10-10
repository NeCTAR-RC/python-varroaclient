#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may
# obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest import mock

from varroaclient.osc import plugin
from varroaclient.tests.unit.osc import base


class TestPlugin(base.OSCTestCase):
    def setUp(self):
        super().setUp()
        self.instance = mock.Mock()
        self.instance._api_version = {plugin.API_NAME: "1"}
        self.instance._cli_options.varroa_endpoint = "http://example.com"
        self.instance.session = mock.Mock()

    def test_make_client(self):
        with mock.patch(
            'osc_lib.utils.get_client_class'
        ) as mock_get_client_class:
            mock_client_class = mock.Mock()
            mock_get_client_class.return_value = mock_client_class

            client = plugin.make_client(self.instance)

            mock_get_client_class.assert_called_once_with(
                plugin.API_NAME, "1", plugin.API_VERSIONS
            )
            mock_client_class.assert_called_once_with(
                session=self.instance.session,
                endpoint_override="http://example.com",
            )
            self.assertEqual(client, mock_client_class.return_value)

    def test_build_option_parser(self):
        parser = mock.Mock()
        result_parser = plugin.build_option_parser(parser)

        parser.add_argument.assert_any_call(
            "--os-varroa-api-version",
            metavar="<varroa-api-version>",
            help="Warre API version, default="
            + plugin.DEFAULT_API_VERSION
            + " (Env: OS_WARRE_API_VERSION)",
        )
        parser.add_argument.assert_any_call(
            "--os-varroa-endpoint",
            metavar="<varroa-endpoint>",
            help="Warre API endpoint",
        )
        self.assertEqual(result_parser, parser)
