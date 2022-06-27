from pypsrp.client import Client
import re


def av_check(host, user, passwd):
    index = 4
    digits = [1, 1, 1, 1]
    signatures_state = False

    client = Client(host, username=user,
                    password=passwd, ssl=False)

    script = r"Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct"

    output, streams, had_errors = client.execute_ps(script)

    p1 = re.compile(r"displayName.*: (.*)")
    result1 = p1.search(output)

    p2 = re.compile(r"productState.*: (.*)")
    result2 = p2.search(output)

    av_name = result1.group(1)
    av_state = result2.group(1)
    av_state = int(av_state)

    conversion_table = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F']
    decimal = av_state
    hexadecimal = ''

    while decimal > 0:
        remainder = decimal % 16
        hexadecimal = conversion_table[remainder] + hexadecimal
        decimal = decimal // 16

    converted = int(hexadecimal)

    while index != 0:
        digits[index-1] = converted % 10
        converted = int(converted / 10)
        index = index - 1

    enable_state = digits[0]

    if digits[2] == 0:
        signatures_state = True

    return enable_state, signatures_state, av_name
