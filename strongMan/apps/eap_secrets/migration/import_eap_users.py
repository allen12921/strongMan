#!/usr/bin/env python3
"""
Import EAP users into a new strongMan instance via its REST API.

Usage:
    python import_eap_users.py \
        --input eap_users_export.json \
        --url https://new-server \
        --username admin \
        --password adminpass
"""
import argparse
import http.cookiejar
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


def build_opener():
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    return opener, jar


def get_csrf_from_jar(jar):
    for cookie in jar:
        if cookie.name == 'csrftoken':
            return cookie.value
    return ''


def get_session_from_jar(jar):
    for cookie in jar:
        if cookie.name == 'sessionid':
            return cookie.value
    return ''


def get_session_cookie(base_url, username, password):
    login_url = f'{base_url}/login/'
    opener, jar = build_opener()

    # GET login page — Django sets csrftoken cookie
    with opener.open(login_url) as resp:
        body = resp.read().decode()

    csrf_token = get_csrf_from_jar(jar)

    # Fallback: read csrfmiddlewaretoken from HTML form
    if not csrf_token:
        match = re.search(r'name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)', body)
        if not match:
            match = re.search(r'value=["\']([^"\']+)["\'][^>]*name=["\']csrfmiddlewaretoken["\']', body)
        if match:
            csrf_token = match.group(1)

    if not csrf_token:
        print('ERROR: Could not extract CSRF token from login page.')
        sys.exit(1)

    # POST credentials — CookieProcessor sends csrftoken cookie automatically
    payload = urllib.parse.urlencode({
        'username': username,
        'password': password,
        'csrfmiddlewaretoken': csrf_token,
    }).encode()

    req = urllib.request.Request(
        login_url,
        data=payload,
        method='POST',
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': login_url,
        },
    )

    try:
        opener.open(req)
    except urllib.error.HTTPError:
        pass  # Django redirects to / after login; treat any redirect as success

    session_id = get_session_from_jar(jar)
    # Refresh csrf_token in case Django rotated it after login
    csrf_token = get_csrf_from_jar(jar) or csrf_token

    if not session_id:
        print('ERROR: Login failed — check username and password.')
        sys.exit(1)

    return csrf_token, session_id


def create_user(opener, base_url, csrf_token, username, password):
    url = f'{base_url}/eap_secrets/api/create'
    payload = json.dumps({'username': username, 'password': password}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        method='POST',
        headers={
            'Content-Type': 'application/json',
            'X-CSRFToken': csrf_token,
            'Referer': f'{base_url}/',
        },
    )
    try:
        with opener.open(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True, help='Path to exported JSON file')
    parser.add_argument('--url', required=True, help='Base URL of new strongMan instance')
    parser.add_argument('--username', required=True, help='Admin username for login')
    parser.add_argument('--password', required=True, help='Admin password for login')
    args = parser.parse_args()

    with open(args.input) as f:
        data = json.load(f)
    users = data.get('users', [])

    if not users:
        print('No users found in input file.')
        return

    print(f'Logging in to {args.url} ...')
    opener, jar = build_opener()

    login_url = f'{args.url}/login/'
    with opener.open(login_url) as resp:
        body = resp.read().decode()

    csrf_token = get_csrf_from_jar(jar)
    if not csrf_token:
        match = re.search(r'name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)', body)
        if not match:
            match = re.search(r'value=["\']([^"\']+)["\'][^>]*name=["\']csrfmiddlewaretoken["\']', body)
        if match:
            csrf_token = match.group(1)

    if not csrf_token:
        print('ERROR: Could not extract CSRF token.')
        sys.exit(1)

    payload = urllib.parse.urlencode({
        'username': args.username,
        'password': args.password,
        'csrfmiddlewaretoken': csrf_token,
    }).encode()

    req = urllib.request.Request(
        login_url,
        data=payload,
        method='POST',
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': login_url,
        },
    )
    try:
        opener.open(req)
    except urllib.error.HTTPError:
        pass

    session_id = get_session_from_jar(jar)
    csrf_token = get_csrf_from_jar(jar) or csrf_token

    if not session_id:
        print('ERROR: Login failed — check username and password.')
        sys.exit(1)

    print('Login successful.\n')

    created = skipped = failed = 0
    for user in users:
        status, resp = create_user(opener, args.url, csrf_token, user['username'], user['password'])
        if status == 201:
            print(f'  [OK]      {user["username"]}')
            created += 1
        elif status == 409:
            print(f'  [SKIP]    {user["username"]} — already exists')
            skipped += 1
        else:
            print(f'  [FAIL]    {user["username"]} — {resp.get("error", status)}')
            failed += 1

    print(f'\nDone: {created} created, {skipped} skipped, {failed} failed.')


if __name__ == '__main__':
    main()
