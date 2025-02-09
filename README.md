# Varroa Client

Client for Varroa

For more information, see https://github.com/NeCTAR-RC/varroa/

## Installation

 pip install varroaclient

## Common openstack CLI Commands

### IP History
Varroa will keep track of what openstack resource owned an IP address for what period

#### To list the resource history of an IP address
```
openstack ip history 203.0.113.1
```

### Security Risk Type
A security risk type is an admin defined type of security risk.
e.g. "Password SSH allowed"

A security risk type has a name and a description. The description should describe what the security risk is and ideally the steps taken to fix this risk.
#### Some example commands
```
openstack security risk type list
openstack security risk type show <security risk type id>
openstack security risk type set <security risk type id>
openstack security risk type create <name>
openstack security risk type delete <security risk type id>
```

### Security Risks
A security risk is the linkage of a security risk type to an openstack resource.
e.g. Compute instance with id XYZ has a "Password SSH allowed" security risk.

Only the IP address of the affected resource needs to be entered when creating a new security risk. Varroa will then process this entry and attempt to link that IP address to an Openstack resource.
#### Some example commands
```
openstack security risk list --all
openstack security risk show <security risk id>
openstack security risk create -i <ip address> <type> -t <time in following format YYYY-MM-DDTHH:MM:SS+HH:MM> -e <expires in following format YYYY-MM-DDTHH:MM:SS+HH:MM>
openstack security risk delete <security risk id>
