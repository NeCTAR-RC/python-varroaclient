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

from nectarclient_lib import exceptions

from varroaclient import client
from varroaclient.v1 import ip_usage
from varroaclient.v1 import security_risk_types
from varroaclient.v1 import security_risks


class Client(object):
    """Client for Varroa v1 API
    :param string session: session
    :type session: :py:class:`keystoneauth.adapter.Adapter`
    """

    def __init__(self, session=None, service_type='security',
                 **kwargs):
        """Initialize a new client for the Varroa v1 API."""
        if session is None:
            raise exceptions.ClientException(
                message='Session is required argument')
        self.http_client = client.SessionClient(
            session, service_type=service_type, **kwargs)
        self.ip_usage = ip_usage.IPUsageManager(self.http_client)
        self.security_risks = security_risks.SecurityRiskManager(
            self.http_client)
        self.security_risk_types = security_risk_types.SecurityRiskTypeManager(
            self.http_client)
