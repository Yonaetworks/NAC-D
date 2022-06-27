import re, uuid

mac = (':'.join(re.findall('..', '%012x' % uuid.getnode())))
print(mac)
