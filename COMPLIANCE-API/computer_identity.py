#!/usr/bin/env python

"""computer_identity.py: Computer Domain verification."""

__author__      = "Yonariel Hernandez & Luis Cofresi"

from pypsrp.client import Client
import re

def computer_hostname(pc_ip, user, passwd):

    client1 = Client(pc_ip, username=user,
                    password=passwd, ssl=False)

    script = r"hostname"

    output, streams, had_errors = client1.execute_ps(script)

    pc_hostname = str(output)

    return pc_hostname

def computer_list(host, user, passwd):

    client = Client(host, username=user,
                    password=passwd, ssl=False)

    script = r"Get-ADComputer -Filter * | FT Name"
    
    output, streams, had_errors = client.execute_ps(script)

    computer_list = re.findall(r"\S*\S",output)

    del computer_list[0:2]

    return computer_list

def computer_verification(pc_ip, user, passwd):

    hostname = computer_hostname(pc_ip, user, passwd)
    computers = computer_list(pc_ip, user, passwd)

    if hostname == computers[computers.index(str(hostname))]:
        return hostname, 1
    else:
        return hostname, 0