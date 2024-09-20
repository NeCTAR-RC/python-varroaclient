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
import itertools
import logging

from osc_lib.command import command
from osc_lib import utils


class ListLimits(command.Lister):
    """List flavors."""

    log = logging.getLogger(__name__ + ".ListFlavors")

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        client = self.app.client_manager.varroa
        kwargs = {}
        if parsed_args.project_id:
            kwargs["project_id"] = parsed_args.project_id
        limits = client.limits.get(**kwargs)
        columns = ["Name", "Value"]
        return (
            columns,
            (
                utils.get_item_properties(s, columns)
                for s in itertools.chain(limits.absolute)
            ),
        )

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        parser.add_argument(
            "--project-id", help="List limits for project_id (admin only)"
        )
        return parser
