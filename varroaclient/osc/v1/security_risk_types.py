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

import logging

from nectarclient_lib import exceptions
from osc_lib.command import command
from osc_lib import utils as osc_utils


class ListSecurityRiskTypes(command.Lister):
    """List security_risk_types."""

    log = logging.getLogger(__name__ + '.ListSecurityRiskTypes')

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        client = self.app.client_manager.varroa
        security_risk_types = client.security_risk_types.list()
        columns = ['id', 'name', 'description']
        return (
            columns,
            (osc_utils.get_item_properties(q, columns)
             for q in security_risk_types)
        )


class SecurityRiskTypeCommand(command.ShowOne):

    def get_parser(self, prog_name):
        parser = super(SecurityRiskTypeCommand, self).get_parser(prog_name)
        parser.add_argument(
            'id',
            metavar='<id>',
            help=('ID of security_risk_type')
        )
        return parser

    def _get_security_risk_type(self, id_or_name):
        client = self.app.client_manager.varroa
        security_risk_type = osc_utils.find_resource(
            client.security_risk_types,
            id_or_name)
        return security_risk_type


class ShowSecurityRiskType(SecurityRiskTypeCommand):
    """Show security_risk_type details."""

    log = logging.getLogger(__name__ + '.ShowSecurityRiskType')

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        security_risk_type = self._get_security_risk_type(parsed_args.id)
        return self.dict2columns(security_risk_type.to_dict())


class CreateSecurityRiskType(command.ShowOne):
    """Create an security_risk_type."""

    log = logging.getLogger(__name__ + '.CreateSecurityRiskType')

    def get_parser(self, prog_name):
        parser = super(CreateSecurityRiskType, self).get_parser(prog_name)
        parser.add_argument(
            'name',
            metavar='<name>',
            help='Name of the security_risk_type'
        )
        parser.add_argument(
            '--description',
            metavar='<description>',
            help='Description of the security_risk_type'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        client = self.app.client_manager.varroa

        fields = {'name': parsed_args.name,
                  'description': parsed_args.description}

        security_risk_type = client.security_risk_types.create(**fields)
        security_risk_type_dict = security_risk_type.to_dict()
        return self.dict2columns(security_risk_type_dict)


class UpdateSecurityRiskType(SecurityRiskTypeCommand):
    """Update a security_risk_type."""

    log = logging.getLogger(__name__ + '.UpdateSecurityRiskType')

    def get_parser(self, prog_name):
        parser = super(UpdateSecurityRiskType, self).get_parser(prog_name)
        parser.add_argument(
            '--name',
            metavar='<name>',
            help="Name"
        )
        parser.add_argument(
            '--description',
            metavar='<description>',
            help='Description of the security_risk_type'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        client = self.app.client_manager.varroa

        security_risk_type = self._get_security_risk_type(parsed_args.id)

        data = {}
        if parsed_args.description:
            data['description'] = parsed_args.description
        if parsed_args.name:
            data['name'] = parsed_args.name
        security_risk_type = client.security_risk_types.update(
            security_risk_type_id=security_risk_type.id, **data)
        security_risk_type_dict = security_risk_type.to_dict()
        return self.dict2columns(security_risk_type_dict)


class DeleteSecurityRiskType(SecurityRiskTypeCommand):
    """Delete security_risk_type."""

    log = logging.getLogger(__name__ + '.DeleteSecurityRiskType')

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        client = self.app.client_manager.varroa

        security_risk_type = self._get_security_risk_type(parsed_args.id)
        try:
            client.security_risk_types.delete(security_risk_type.id)
        except exceptions.NotFound as ex:
            raise exceptions.CommandError(str(ex))

        return [], []
