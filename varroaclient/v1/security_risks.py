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

from nectarclient_lib import base

from varroaclient.v1 import security_risk_types


class SecurityRisk(base.Resource):
    date_fields = ["time", "expires", "first_seen", "last_seen"]

    def __init__(self, manager, info, loaded=False, resp=None):
        super().__init__(manager, info, loaded, resp)
        self.type = security_risk_types.SecurityRiskType(
            None, self.type, loaded=True
        )

    def __repr__(self):
        return f"<SecurityRisk {self.id}>"

    def to_dict(self):
        res = super().to_dict()
        res["type"] = res.get("type", {}).get("name")
        return res


class SecurityRiskManager(base.BasicManager):
    base_url = "v1/security-risks"
    resource_class = SecurityRisk

    def delete(self, security_risk_id):
        return self._delete(f"/{self.base_url}/{security_risk_id}/")

    def create(
        self,
        time,
        expires,
        type_id,
        ipaddress=None,
        port=None,
        project_id=None,
        resource_id=None,
        resource_type=None,
    ):
        """Create a security risk.

        A risk is reported either by IP address (ipaddress, optionally
        port) or by resource (project_id, resource_id and resource_type
        together), never both.
        """
        data = {
            "time": time,
            "expires": expires,
            "type_id": type_id,
            "ipaddress": ipaddress,
            "port": port,
            "project_id": project_id,
            "resource_id": resource_id,
            "resource_type": resource_type,
        }
        # Omit unset fields so payloads stay compatible with servers that
        # predate resource-first risks.
        data = {k: v for k, v in data.items() if v is not None}
        return self._create(f"/{self.base_url}/", data=data)
