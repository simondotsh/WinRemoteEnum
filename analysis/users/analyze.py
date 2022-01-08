#!/usr/bin/env python3

from argparse import ArgumentParser
from os.path import isfile, expanduser
from json import load, dumps, decoder

COMPROMISED_FILE = 'compromised_users.txt'
REMOTE_ACCESS_RIDS = [544, 555, 580]
POTENTIAL_REMOTE_ACCESS_RIDS = [559, 562]

def main():
    args = parse_args()
    results = get_results(args.users_results)
    users_filter = get_users(args.filter)
    output = {}

    for target in results:
        if target['results']:
            output[target['target']] = get_remote_groups(
                target['results']['groups'], users_filter
            )
        else:
            output[target['target']] = []

    print(dumps(output, indent=4))

def parse_args():
    parser = ArgumentParser()
    parser.add_argument('users_results', 
        help='Path of the users.json file to analyze.'
    )
    parser.add_argument('-f', '--filter', dest='filter', 
        action='store_true', default=False,
        help='The script will only output members of groups that are '
             'specified in the compromised_users.txt file.'
    )

    args = parser.parse_args()
    return args

def get_results(users_results):
    users_results = expanduser(users_results)

    if not isfile(users_results):
        print(f'{users_results}: No such file.')
        exit(0)

    try:
        with open(users_results) as f:
            results = load(f)
    except decoder.JSONDecodeError:
        print(f'{users_results}: Invalid JSON file.')
        exit(0)

    return results

def get_users(filter):
    if not filter:
        return []

    if not isfile(COMPROMISED_FILE):
        print(f'{COMPROMISED_FILE}: No such file.')
        exit(0)

    with open(COMPROMISED_FILE) as f:
        return f.read().lower().splitlines()

def get_remote_groups(groups, users_filter):
    remote_groups = []

    for group in groups:
        if len(group['members']):
            if group['rid'] in REMOTE_ACCESS_RIDS:
                group['access_certainty'] = 'certain'
            elif group['rid'] in POTENTIAL_REMOTE_ACCESS_RIDS:
                group['access_certainty'] = 'potential'
            else:
                continue

            if users_filter:
                filtered_members = filter_members(group, users_filter)

                if filtered_members:
                    group['members'] = filtered_members
                    remote_groups.append(group)
                else:
                    continue
            else:
                remote_groups.append(group)

    return remote_groups

def filter_members(group, users_filter):
    members = []

    for member in group['members']:
        if member['name'].lower() in users_filter:
            members.append(member)

    return members
    
if __name__ == '__main__':
    main()