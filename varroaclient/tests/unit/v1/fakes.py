#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import re
from unittest import mock
from urllib import parse

from nectarclient_lib.tests.unit import fakes
from nectarclient_lib.tests.unit import utils


from varroaclient import client as base_client
from varroaclient.v1 import client
from varroaclient.v1 import ip_usage
from varroaclient.v1 import security_risk_types
from varroaclient.v1 import security_risks


# regex to compare callback to result of get_endpoint()
# checks version number (vX or vX.X where X is a number)
# and also checks if the id is on the end
ENDPOINT_RE = re.compile(
    r"^get_http:__varroa_api:8774_v\d(_\d)?_\w{32}$")

# accepts formats like v2 or v2.1
ENDPOINT_TYPE_RE = re.compile(r"^v\d(\.\d)?$")

# accepts formats like v2 or v2_1
CALLBACK_RE = re.compile(r"^get_http:__varroa_api:8774_v\d(_\d)?$")

generic_ip_usage = {
    "ip": "203.0.113.1",
    "project_id": "5a4c814a4b9a472f848c4876f4695866",
    "port_id": "d1c8143f-f051-482e-8532-6b1422ddaf98",
    "resource_id": "a8c4a8d3-78b5-43ac-8dc1-1c9963cd7627",
    "resource_type": "instance",
    "start": "2024-09-10T00:29:15+00:00",
    "end": None
}

generic_sr_type = {
    "id": "64471818-c829-4839-8aa7-8393fa050438",
    "name": "db-exposed",
    "description": "Database service exposed to the Internet"
}

generic_sr = {
    "type": generic_sr_type,
    "id": "27b856fb-fc35-43b6-a539-704fc6fb19ad",
    "status": "PROCESSED",
    "time": "2024-09-16T15:20:45+00:00",
    "ipaddress": "203.0.113.1",
    "port": None,
    "expires": "2024-09-20T23:46:45+00:00",
    "project_id": "094ae1d2c08f4eddb434a9d9db71ab40",
    "resource_id": "218d88fc-df13-445f-b57a-687b3d84fca5",
    "resource_type": "instance"
}


class FakeClient(fakes.FakeClient, client.Client):

    def __init__(self, *args, **kwargs):
        client.Client.__init__(self, session=mock.Mock())
        self.http_client = FakeSessionClient(**kwargs)
        self.ip_usage = ip_usage.IPUsageManager(self.http_client)
        self.security_risks = security_risks.SecurityRiskManager(
            self.http_client)
        self.security_risk_types = security_risk_types.SecurityRiskTypeManager(
            self.http_client)


class FakeSessionClient(base_client.SessionClient):

    def __init__(self, *args, **kwargs):

        self.callstack = []
        self.visited = []
        self.auth = mock.Mock()
        self.session = mock.Mock()
        self.service_type = 'service_type'
        self.service_name = None
        self.endpoint_override = None
        self.interface = None
        self.region_name = None
        self.version = None
        self.auth.get_auth_ref.return_value.project_id = 'tenant_id'
        # determines which endpoint to return in get_endpoint()
        # NOTE(augustina): this is a hacky workaround, ultimately
        # we need to fix our whole mocking architecture (fixtures?)
        if 'endpoint_type' in kwargs:
            self.endpoint_type = kwargs['endpoint_type']
        else:
            self.endpoint_type = 'endpoint_type'
        self.logger = mock.MagicMock()

    def request(self, url, method, **kwargs):
        return self._cs_request(url, method, **kwargs)

    def _cs_request(self, url, method, **kwargs):
        # Check that certain things are called correctly
        if method in ['GET', 'DELETE']:
            assert 'data' not in kwargs
        elif method == 'PUT':
            assert 'data' in kwargs

        if url is not None:
            # Call the method
            args = parse.parse_qsl(parse.urlparse(url)[4])
            kwargs.update(args)
            munged_url = url.rsplit('?', 1)[0]
            munged_url = munged_url.strip('/').replace('/', '_')
            munged_url = munged_url.replace('.', '_')
            munged_url = munged_url.replace('-', '_')
            munged_url = munged_url.replace(' ', '_')
            munged_url = munged_url.replace('!', '_')
            munged_url = munged_url.replace('@', '_')
            munged_url = munged_url.replace('%20', '_')
            munged_url = munged_url.replace('%3A', '_')
            callback = "%s_%s" % (method.lower(), munged_url)

        if not hasattr(self, callback):
            raise AssertionError('Called unknown API method: %s %s, '
                                 'expected fakes method name: %s' %
                                 (method, url, callback))

        # Note the call
        self.visited.append(callback)
        self.callstack.append((method, url, kwargs.get('data'),
                               kwargs.get('params')))

        status, headers, data = getattr(self, callback)(**kwargs)

        r = utils.TestResponse({
            "status_code": status,
            "text": data,
            "headers": headers,
        })
        return r, data

    def get_v1_ip_usage(self, **kw):
        ip_usage_list = [generic_ip_usage]
        return (200, {}, ip_usage_list)

    def get_v1_security_risks(self, **kw):
        security_risks = [
            {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "time": "2024-03-15T14:30:00Z",
                "type": generic_sr_type,
                "expires": "2024-03-22T14:30:00Z",
                "ipaddress": "192.168.1.100",
                "port": 22
            },
            {
                "id": "550e8400-e29b-41d4-a716-446655440001",
                "time": "2024-03-15T15:45:00Z",
                "type": generic_sr_type,
                "expires": "2024-03-18T15:45:00Z",
                "ipaddress": "192.168.1.101",
                "port": None
            }
        ]
        return (200, {}, security_risks)

    def get_v1_security_risks_risk_id(self, **kw):
        risk_detail = {
            "id": "550e8400-e29b-41d4-a716-446655440001",
            "time": "2024-03-15T14:30:00Z",
            "type": generic_sr_type,
            "expires": "2024-03-22T14:30:00Z",
            "ipaddress": "192.168.1.100",
            "port": 22
        }
        return (200, {}, risk_detail)

    def delete_v1_security_risks_risk_id(self, **kw):
        return (204, {}, '')

    def post_v1_security_risks(self, **kw):
        new_risk = {
            "id": "550e8400-e29b-41d4-a716-446655440002",
            "time": kw.get('time', "2024-03-16T10:00:00Z"),
            "type": kw.get('type_id', generic_sr_type),
            "expires": kw.get('expires', "2024-03-23T10:00:00Z"),
            "ipaddress": kw.get('ipaddress', "192.168.1.102"),
            "port": kw.get('port', 80)
        }
        return (201, {}, new_risk)

    def get_v1_security_risk_types(self, **kw):
        security_risk_types = [
            {
                "id": "type-id-1",
                "name": "Test Risk Type 1",
                "description": "This is test risk type 1"
            },
            {
                "id": "type-id-2",
                "name": "Test Risk Type 2",
                "description": "This is test risk type 2"
            }
        ]
        return (200, {}, security_risk_types)

    def get_v1_security_risk_types_type_id(self, **kw):
        risk_type_detail = {
            "id": "type-id-1",
            "name": "Test Risk Type 1",
            "description": "This is test risk type 1"
        }
        return (200, {}, risk_type_detail)

    def delete_v1_security_risk_types_type_id(self, **kw):
        return (204, {}, '')

    def post_v1_security_risk_types(self, **kw):
        new_risk_type = {
            "id": "new-type-id",
            "name": kw.get('name', "New Risk Type"),
            "description": kw.get('description', "This is a new risk type")
        }
        return (201, {}, new_risk_type)

    def patch_v1_security_risk_types_type_id(self, **kw):
        updated_risk_type = {
            "id": "type-id-1",
            "name": kw.get('name', "Updated Risk Type"),
            "description": kw.get(
                'description', "This is an updated risk type")
        }
        return (200, {}, updated_risk_type)
