import pkg_resources
import re

with open('requirements.txt', 'r') as f:
    reqs = f.read().splitlines()

installed = {pkg.key for pkg in pkg_resources.working_set}

missing = []
for req in reqs:
    if req.strip() and not req.startswith('#'):
        pkg_name = re.split(r'[>=<~!]', req)[0].strip()
        if pkg_name.lower() not in installed:
            missing.append(pkg_name)

print('Missing packages:', missing)