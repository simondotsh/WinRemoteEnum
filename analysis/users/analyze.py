#!/usr/bin/env python3

from argparse import ArgumentParser
from os.path import isfile, expanduser
import json

from impacket.dcerpc.v5.samr import GROUP_MEMBERSHIP

remote_access_rid = [544, 555, 580]
uncertain_remote_access_rid = [559, 562]

parser = ArgumentParser()
parser.add_argument('file', help='Path of the users.json file to analyze.')

args = parser.parse_args()
file = expanduser(args.file)

if not isfile(file):
    print(f'{file}: No such file.')
    exit(0)

try:
    with open(file) as f:
        results = json.load(f)
except json.decoder.JSONDecodeError:
    print(f'{file}: Invalid JSON file.')
    exit(0)

for target in results:
    for group in target['results']['groups']:
        if group['rid'] in remote_access_rid:
            print(group)
            continue

        if group['rid'] in uncertain_remote_access_rid:
            print(group)

            
