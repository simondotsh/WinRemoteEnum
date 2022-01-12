#!/usr/bin/env python3

from argparse import ArgumentParser
from os.path import join, dirname, realpath, isfile, expanduser
from json import load, dumps, decoder

FILTER_FILE = join(dirname(realpath(__file__)), 'principals_filter.txt')
REMOTE_ACCESS_RIDS = [544, 555, 580]
POTENTIAL_REMOTE_ACCESS_RIDS = [559, 562]

def main():
    args = parse_args()
    results = get_results(args.users_results)
    principals_filter = get_principals(args.filter)
    output = {}

    for target in results:
        if target['results']:
            output[target['target']] = get_remote_groups(
                target['results']['groups'], principals_filter
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
        help='Instead of outputting all members of the groups, '
             'this will list only those specified in the principals_filter file.'
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

def get_principals(filter):
    if not filter:
        return []

    if not isfile(FILTER_FILE):
        print(f'{FILTER_FILE}: No such file.')
        exit(0)

    with open(FILTER_FILE) as f:
        return f.read().lower().splitlines()

def get_remote_groups(groups, principals_filter):
    remote_groups = []

    for group in groups:
        if len(group['members']):
            if group['rid'] in REMOTE_ACCESS_RIDS:
                group['access_certainty'] = 'certain'
            elif group['rid'] in POTENTIAL_REMOTE_ACCESS_RIDS:
                group['access_certainty'] = 'potential'
            else:
                continue

            if principals_filter:
                filtered_members = filter_members(group, principals_filter)

                if filtered_members:
                    group['members'] = filtered_members
                    remote_groups.append(group)
                else:
                    continue
            else:
                remote_groups.append(group)

    return remote_groups

def filter_members(group, principals_filter):
    members = []

    for member in group['members']:
        if member['name'].lower() in principals_filter:
            members.append(member)

    return members
    
if __name__ == '__main__':
    main()