#!/usr/bin/env python3
"""
Parse auth.log (or provided file) and list top failed login IPs & usernames.
"""
import argparse
import re
from collections import Counter

FAILED_PATTERNS = [
    re.compile(r'Failed password for (invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)'),
    re.compile(r'authentication failure; .* rhost=(\d+\.\d+\.\d+\.\d+)'),
]

def parse_file(path):
    ip_counter = Counter()
    user_counter = Counter()
    with open(path, 'r', errors='ignore') as f:
        for line in f:
            for pat in FAILED_PATTERNS:
                m = pat.search(line)
                if m:
                    if 'rhost' in pat.pattern:
                        ip = m.group(1)
                        ip_counter[ip] += 1
                    else:
                        user = m.group(2)
                        ip = m.group(3)
                        user_counter[user] += 1
                        ip_counter[ip] += 1
    return ip_counter, user_counter

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--file', default='/var/log/auth.log', help='path to auth log or sample')
    args = p.parse_args()
    ips, users = parse_file(args.file)
    print("Top IPs with failed logins:")
    for ip, count in ips.most_common(10):
        print(f"{ip}\t{count}")
    print("\nTop usernames targeted:")
    for u, c in users.most_common(10):
        print(f"{u}\t{c}")

if __name__ == '__main__':
    main()
