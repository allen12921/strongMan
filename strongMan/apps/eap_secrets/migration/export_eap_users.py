#!/usr/bin/env python3
"""
Export EAP users from strongMan database to JSON.

Usage (run from project root):
    python strongMan/apps/eap_secrets/migration/export_eap_users.py
    python strongMan/apps/eap_secrets/migration/export_eap_users.py --output /tmp/eap_users.json
"""
import argparse
import json
import os
import sys

# Bootstrap Django: go up 4 levels from this file's directory to project root
_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_here, '../../../..')))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'strongMan.settings.production')

import django
django.setup()

from strongMan.apps.eap_secrets.models import Secret

SALT_LENGTH = 32


def export(output_path):
    secrets = Secret.objects.filter(type='EAP')
    count = secrets.count()

    if count == 0:
        print('No EAP users found.')
        return

    users = []
    for secret in secrets:
        # password field = salt[32 chars] + plaintext; ORM decrypts automatically
        users.append({
            'username': secret.username,
            'password': secret.password[SALT_LENGTH:],
            'type': secret.type,
        })

    with open(output_path, 'w') as f:
        json.dump({'users': users}, f, indent=2)

    print(f'Exported {count} EAP user(s) to {os.path.abspath(output_path)}')
    print('WARNING: file contains plaintext passwords — delete after migration.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='eap_users_export.json')
    args = parser.parse_args()
    export(args.output)
