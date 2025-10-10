import re

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+")
IP_PATTERN = re.compile(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}")
DOMAIN_PATTERN = re.compile(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}")
