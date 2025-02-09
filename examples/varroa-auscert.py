#!/usr/bin/env python

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

import argparse
import csv
import datetime
import re

import openstack
from varroaclient import client


TYPE_MAP = {
    re.compile(r'accessible-postgresql'): 'accessible-db',
    re.compile(r'accessible-mysql'): 'accessible-db',
    re.compile(r'accessible-rdp'): 'accessible-rdp',
    re.compile(r'vulnerable-http'): 'vulnerable-http',
    re.compile(r'accessible-ssh'): 'password-ssh',
}


def process(conn, scan_file):
    varroa = client.Client('1', session=conn.session)

    sr_types = varroa.security_risk_types.list()
    sr_type_id_map = {s.name: s.id for s in sr_types}

    scan_reader = csv.reader(scan_file)
    for row in scan_reader:
        ip = row[0]
        message = row[1]
        time = row[2]
        port = row[3]
        matched_type = None
        for signature, sr_type in TYPE_MAP.items():
            if signature.search(message):
                matched_type = sr_type
                break  # Exit the loop after the first match
        if matched_type:
            type_id = sr_type_id_map.get(matched_type)
            time_dt = datetime.datetime.strptime(time, '%Y-%m-%dT%H:%M:%S%z')
            expires = time_dt + datetime.timedelta(days=7)
            varroa.security_risks.create(
                ipaddress=ip,
                port=port,
                type_id=type_id,
                time=time_dt.isoformat(),
                expires=expires.isoformat(),
            )
            print(f"Successfully matched {ip} to {matched_type}")
        else:
            print(f"Couldn't find match for {message}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='varroa-auscert',
        description='Parse AusCert CSV and send to varroa',
    )

    parser.add_argument('file', type=argparse.FileType('r'))

    args = parser.parse_args()
    conn = openstack.connect()
    process(conn, args.file)
