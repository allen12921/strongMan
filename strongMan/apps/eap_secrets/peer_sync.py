import http.cookiejar
import json
import logging
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
RETRY_DELAYS = [1, 2, 4]  # seconds


HTTP_TIMEOUT = 10  # seconds


def _login(base_url, username, password):
    """Login to a peer instance and return a cookie-aware opener."""
    login_url = f'{base_url}/login/'
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    with opener.open(login_url, timeout=HTTP_TIMEOUT) as resp:
        body = resp.read().decode()

    csrf_token = next((c.value for c in jar if c.name == 'csrftoken'), '')
    if not csrf_token:
        match = re.search(r'name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)', body)
        if not match:
            match = re.search(r'value=["\']([^"\']+)["\'][^>]*name=["\']csrfmiddlewaretoken["\']', body)
        if match:
            csrf_token = match.group(1)

    if not csrf_token:
        raise RuntimeError(f'peer_sync: could not obtain CSRF token from {login_url}')

    payload = urllib.parse.urlencode({
        'username': username,
        'password': password,
        'csrfmiddlewaretoken': csrf_token,
    }).encode()

    req = urllib.request.Request(
        login_url, data=payload, method='POST',
        headers={'Content-Type': 'application/x-www-form-urlencoded', 'Referer': login_url},
    )
    try:
        opener.open(req, timeout=HTTP_TIMEOUT)
    except urllib.error.HTTPError:
        pass

    return opener, next((c.value for c in jar if c.name == 'csrftoken'), csrf_token)


def _call_api(opener, base_url, csrf_token, action, username, password=''):
    if action == 'create':
        url = f'{base_url}/eap_secrets/api/create'
        data = json.dumps({'username': username, 'password': password}).encode()
        method = 'POST'
    else:
        url = f'{base_url}/eap_secrets/api/{username}/delete'
        data = b''
        method = 'DELETE'

    req = urllib.request.Request(
        url, data=data, method=method,
        headers={
            'Content-Type': 'application/json',
            'X-CSRFToken': csrf_token,
            'Referer': f'{base_url}/',
        },
    )
    try:
        with opener.open(req, timeout=HTTP_TIMEOUT) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read())
        except Exception:
            body = {}
        return e.code, body


def _call_api_upsert(opener, base_url, csrf_token, username, password):
    """Create or replace: try create; on 409 delete then re-create."""
    status, resp = _call_api(opener, base_url, csrf_token, 'create', username, password)
    if status == 409:
        logger.info('peer_sync: upsert %s on %s: 409, replacing existing credential', username, base_url)
        del_status, del_resp = _call_api(opener, base_url, csrf_token, 'delete', username, '')
        if del_status not in (200, 201, 404):
            err = del_resp.get('error', str(del_status)) if isinstance(del_resp, dict) else str(del_status)
            logger.warning('peer_sync: upsert delete step failed for %s on %s: %s', username, base_url, err)
            return del_status, del_resp
        status, resp = _call_api(opener, base_url, csrf_token, 'create', username, password)
    return status, resp


def _sync_to_peer(peer, action, username, password):
    """Push one action to one peer with retries. Saves SyncFailure on exhaustion.

    action:
      'create' — upsert (409 → delete + re-create)
      'delete' — plain delete
      'update' — delete then upsert, in sequence within the same thread
    """
    from .models import SyncFailure

    url = peer['url']
    last_error = ''
    for attempt, delay in enumerate(RETRY_DELAYS):
        try:
            opener, csrf = _login(url, peer['username'], peer['password'])
            if action == 'update':
                # delete first (ignore errors — credential may not exist on peer yet)
                _call_api(opener, url, csrf, 'delete', username, '')
                status, resp = _call_api_upsert(opener, url, csrf, username, password)
            elif action == 'create':
                status, resp = _call_api_upsert(opener, url, csrf, username, password)
            else:
                status, resp = _call_api(opener, url, csrf, action, username, password)

            if status in (200, 201) or (action == 'delete' and status == 404):
                logger.info('peer_sync: %s %s -> %s OK', action, username, url)
                return
            last_error = resp.get('error', str(status)) if isinstance(resp, dict) else str(status)
        except Exception as exc:
            last_error = str(exc)

        logger.warning('peer_sync: attempt %d failed for %s %s -> %s: %s',
                       attempt + 1, action, username, url, last_error)
        if attempt < len(RETRY_DELAYS) - 1:
            time.sleep(delay)

    logger.error('peer_sync: all retries exhausted for %s %s -> %s, saving SyncFailure', action, username, url)
    SyncFailure.objects.create(
        peer_url=url,
        action=action,
        username=username,
        password=password if action in ('create', 'update') else '',
        last_error=last_error,
    )


def _get_peers():
    from .models import SyncPeer
    # Use model instances (not .values()) so EncryptedTextField.from_db_value decrypts passwords
    return [{'url': p.url, 'username': p.username, 'password': p.password}
            for p in SyncPeer.objects.all()]


def _push(action, username, password=''):
    peers = _get_peers()
    if not peers:
        return

    def run():
        threads = [
            threading.Thread(target=_sync_to_peer, args=(peer, action, username, password), daemon=True)
            for peer in peers
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    threading.Thread(target=run, daemon=True).start()


def push_create(username, password):
    _push('create', username, password)


def push_delete(username):
    _push('delete', username)


def push_update(username, password):
    _push('update', username, password)


def full_sync_to_peers():
    """Upsert every local EAP user to all configured peers (fire-and-forget).

    Returns a summary dict: {total, peers, dispatched}.
    """
    from strongMan.apps.eap_secrets.models import Secret

    peers = _get_peers()
    if not peers:
        return {'total': 0, 'peers': 0, 'dispatched': False}

    secrets = list(Secret.objects.filter(type='EAP'))
    if not secrets:
        return {'total': 0, 'peers': len(peers), 'dispatched': False}

    for secret in secrets:
        plaintext = secret.password[len(secret.salt):]
        push_create(secret.username, plaintext)  # push_create uses upsert semantics

    return {'total': len(secrets), 'peers': len(peers), 'dispatched': True}


def retry_failed_syncs():
    """Replay all pending SyncFailure records. Returns a result summary dict."""
    from .models import SyncFailure

    failures = list(SyncFailure.objects.all())
    total = len(failures)
    if total == 0:
        return {'total': 0, 'succeeded': 0, 'failed': 0}

    succeeded = failed = 0
    for failure in failures:
        peer = _peer_config_for(failure.peer_url)
        if peer is None:
            logger.warning('peer_sync: peer %s no longer configured, removing stale SyncFailure', failure.peer_url)
            failure.delete()
            succeeded += 1
            continue
        try:
            opener, csrf = _login(failure.peer_url, peer['username'], peer['password'])
            if failure.action == 'update':
                _call_api(opener, failure.peer_url, csrf, 'delete', failure.username, '')
                status, resp = _call_api_upsert(opener, failure.peer_url, csrf,
                                                failure.username, failure.password)
            elif failure.action == 'create':
                status, resp = _call_api_upsert(opener, failure.peer_url, csrf,
                                                failure.username, failure.password)
            else:
                status, resp = _call_api(opener, failure.peer_url, csrf,
                                         failure.action, failure.username, failure.password)
            # 404 on delete = user already absent on peer, treat as idempotent success
            if status in (200, 201) or (failure.action == 'delete' and status == 404):
                failure.delete()
                succeeded += 1
                logger.info('peer_sync: retry succeeded for %s %s -> %s',
                            failure.action, failure.username, failure.peer_url)
            else:
                failure.last_error = resp.get('error', str(status)) if isinstance(resp, dict) else str(status)
                failure.save()
                failed += 1
        except Exception as exc:
            failure.last_error = str(exc)
            failure.save()
            failed += 1
            logger.warning('peer_sync: retry failed for %s %s -> %s: %s',
                           failure.action, failure.username, failure.peer_url, exc)

    return {'total': total, 'succeeded': succeeded, 'failed': failed}


def _peer_config_for(url):
    for peer in _get_peers():
        if peer['url'].rstrip('/') == url.rstrip('/'):
            return peer
    return None
