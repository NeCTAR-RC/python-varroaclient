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

from openstackclient.identity import common
from osc_lib.command import command
from osc_lib import utils as osc_utils


class ListIPUsage(command.Lister):
    """Show IP usage history."""

    log = logging.getLogger(__name__ + ".ListIp_Usage")

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        parser.add_argument("ip", metavar="<ip>", help="IP address")
        parser.add_argument(
            "--all-projects",
            action="store_true",
            default=True,
            help="List all projects ip_usage (admin only)",
        )
        parser.add_argument(
            "--project",
            metavar="<project>",
            help="Filter by project (name or ID)",
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
        columns = ["ip", "start", "end", "resource_id"]
        if parsed_args.all_projects:
            kwargs["all_projects"] = True
            columns = ["ip", "project_id", "start", "end", "resource_id"]
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
        if parsed_args.ip:
            kwargs["ip"] = parsed_args.ip
        ip_usage = client.ip_usage.list(**kwargs)
        return (
            columns,
            (
                osc_utils.get_item_properties(
                    q, columns, formatters={"start": str, "end": str}
                )
                for q in ip_usage
            ),
        )
