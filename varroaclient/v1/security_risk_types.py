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


class SecurityRiskType(base.Resource):

    def __repr__(self):
        return "<SecurityRiskType %s>" % self.id


class SecurityRiskTypeManager(base.BasicManager):

    base_url = 'v1/security-risk-types'
    resource_class = SecurityRiskType

    def update(self, security_risk_type_id, **kwargs):
        return self._update('/%s/%s/' % (self.base_url, security_risk_type_id),
                            data=kwargs)

    def delete(self, security_risk_type_id):
        return self._delete('/%s/%s/' % (self.base_url, security_risk_type_id))

    def create(self, name, description):
        data = {'name': name,
                'description': description}

        return self._create("/%s/" % self.base_url, data=data)