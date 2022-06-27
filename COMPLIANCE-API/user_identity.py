#!/usr/bin/env python

"""user_identity.py: Domain user verification."""

__author__      = "Yonariel Hernandez & Luis Cofresi"

from pypsrp.client import Client
import re
domain_Name = "NACD"

def user_loggedin(pc_ip, user, passwd):

    client1 = Client(pc_ip, username=user,
                    password=passwd, ssl=False)

    script = r"(Get-WMIObject -ClassName Win32_ComputerSystem).Username"

    output, streams, had_errors = client1.execute_ps(script)

    user_name = str(output)

    return user_name

def user_list(host, user, passwd):

    client = Client(host, username=user,
                    password=passwd, ssl=False)

    script = r"Get-ADUser -Filter * | FT Name"
    
    output, streams, had_errors = client.execute_ps(script)

    user_list = re.findall(r"\S*\S",output)

    del user_list[0:2]

    return user_list

def user_identity(host, user, passwd):

    user = user_loggedin(host, user, passwd)
    userlist = user_list(host, user, passwd)

    user_regex = re.match(domain_Name + r"\\(.*)", user)

    user = user_regex.group(1)

    if user == userlist[userlist.index(str(user))]:
        return user, 1
    else:
        return user, 0