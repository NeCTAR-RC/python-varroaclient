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
from openstackclient.identity import common
from osc_lib.command import command
from osc_lib import utils as osc_utils


class ListSecurityRisks(command.Lister):
    """List security_risks."""

    log = logging.getLogger(__name__ + ".ListSecurityRisks")

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        parser.add_argument(
            "--all-projects",
            action="store_true",
            default=False,
            help="List all projects security_risks (admin only)",
        )
        parser.add_argument(
            "--project",
            metavar="<project>",
            help="Filter by project (name or ID)",
        )
        parser.add_argument(
            "--type", metavar="<type>", help="Filter by type (name or ID)"
        )
        parser.add_argument(
            "--project-domain",
            default="default",
            metavar="<project_domain>",
            help="Project domain to filter (name or ID)",
        )

        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        client = self.app.client_manager.varroa
        kwargs = {}
        columns = ["id", "type", "time", "ipaddress", "port"]
        if parsed_args.all_projects:
            kwargs["all_projects"] = True
            columns = [
                "id",
                "project_id",
                "type",
                "time",
                "ipaddress",
                "port",
                "status",
            ]
        if parsed_args.project:
            identity_client = self.app.client_manager.identity
            project = common.find_project(
                identity_client,
                common._get_token_resource(
                    identity_client, "project", parsed_args.project
                ),
                parsed_args.project_domain,
            )

            kwargs["project_id"] = project.id
            # Assume all_projects if project set
            kwargs["all_projects"] = True
        if parsed_args.type:
            security_risk_type = osc_utils.find_resource(
                client.security_risk_types, parsed_args.type
            )
            kwargs["type_id"] = security_risk_type.id
        security_risks = client.security_risks.list(**kwargs)
        for r in security_risks:
            r.type = r.type.name
        return (
            columns,
            (
                osc_utils.get_item_properties(q, columns)
                for q in security_risks
            ),
        )


class SecurityRiskCommand(command.ShowOne):
    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        parser.add_argument("id", metavar="<id>", help=("ID of security_risk"))
        return parser


class ShowSecurityRisk(SecurityRiskCommand):
    """Show security_risk details."""

    log = logging.getLogger(__name__ + ".ShowSecurityRisk")

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        client = self.app.client_manager.varroa
        try:
            security_risk = client.security_risks.get(parsed_args.id)
        except exceptions.NotFound as ex:
            raise exceptions.CommandError(str(ex))

        return self.dict2columns(security_risk.to_dict())


class CreateSecurityRisk(command.ShowOne):
    """Create a security_risk."""

    log = logging.getLogger(__name__ + ".CreateSecurityRisk")

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        parser.add_argument("type", metavar="type>", help="Type")
        parser.add_argument(
            "-t",
            "--time",
            metavar="<time>",
            help="Time (YYYY-MM-DDTHH:MM:SS+HHMM)",
            required=True,
        )
        parser.add_argument(
            "-e",
            "--expires",
            metavar="<expires>",
            help="Time (YYYY-MM-DDTHH:MM:SS+HHMM)",
            required=True,
        )
        parser.add_argument(
            "-i", "--ipaddress", metavar="<ipaddress>", help="IP address"
        )
        parser.add_argument(
            "-p", "--port", metavar="<port>", default=None, help="Port"
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        client = self.app.client_manager.varroa
        security_risk_type = osc_utils.find_resource(
            client.security_risk_types, parsed_args.type
        )

        fields = {
            "type_id": security_risk_type.id,
            "time": parsed_args.time,
            "expires": parsed_args.expires,
            "ipaddress": parsed_args.ipaddress,
            "port": parsed_args.port,
        }

        security_risk = client.security_risks.create(**fields)
        security_risk_dict = security_risk.to_dict()
        return self.dict2columns(security_risk_dict)


class DeleteSecurityRisk(SecurityRiskCommand):
    """Delete security_risk."""

    log = logging.getLogger(__name__ + ".DeleteSecurityRisk")

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        client = self.app.client_manager.varroa
        try:
            client.security_risks.delete(parsed_args.id)
        except exceptions.NotFound as ex:
            raise exceptions.CommandError(str(ex))

        return [], []
