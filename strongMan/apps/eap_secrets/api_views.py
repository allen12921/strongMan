import json
import re
from base64 import b64encode
from os import urandom

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .models import Secret
from . import peer_sync
from strongMan.helper_apps.vici.wrapper.wrapper import ViciWrapper


@csrf_exempt
@login_required
@require_http_methods(["POST"])
def create_eap_user(request):
    """Create a new EAP user"""
    try:
        data = json.loads(request.body)
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()

        if not username or not password:
            return JsonResponse({
                'success': False,
                'error': 'Username and password are required'
            }, status=400)

        # Salt prefix is 32 chars; Secret.password field max_length=50
        MAX_PASSWORD_LEN = 50 - 32  # = 18
        if len(password) > MAX_PASSWORD_LEN:
            return JsonResponse({
                'success': False,
                'error': f'Password must be at most {MAX_PASSWORD_LEN} characters'
            }, status=400)

        if not re.match(r'^[0-9a-zA-Z_\-]+$', username):
            return JsonResponse({
                'success': False,
                'error': 'Username can only contain letters, numbers, underscore and hyphen'
            }, status=400)

        if Secret.objects.filter(username=username).exists():
            return JsonResponse({
                'success': False,
                'error': f'EAP user "{username}" already exists'
            }, status=409)

        salt = b64encode(urandom(24)).decode('utf-8')
        salted_password = salt + password

        secret = Secret(
            username=username,
            type='EAP',
            password=salted_password,
            salt=salt
        )
        secret.save()
        try:
            ViciWrapper().load_secret(secret.dict())
        except Exception as vici_err:
            secret.delete()
            return JsonResponse({'success': False, 'error': str(vici_err)}, status=500)
        peer_sync.push_create(username, password)

        return JsonResponse({
            'success': True,
            'message': 'EAP user created successfully',
            'data': {'username': username}
        }, status=201)

    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON format'
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
@login_required
@require_http_methods(["DELETE"])
def delete_eap_user(request, username):
    """Delete an EAP user"""
    try:
        secret = Secret.objects.filter(username=username, type='EAP').first()
        
        if not secret:
            return JsonResponse({
                'success': False,
                'error': f'EAP user "{username}" not found'
            }, status=404)

        secret.delete()
        peer_sync.push_delete(username)

        return JsonResponse({
            'success': True,
            'message': f'EAP user "{username}" deleted successfully'
        }, status=200)

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
@login_required
@require_http_methods(["GET"])
def list_eap_users(request):
    """List all EAP users"""
    try:
        secrets = Secret.objects.filter(type='EAP')
        users = [{'username': secret.username} for secret in secrets]

        return JsonResponse({
            'success': True,
            'count': len(users),
            'users': users
        }, status=200)

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
@login_required
@require_http_methods(["GET"])
def get_eap_user(request, username):
    """Get details of a specific EAP user"""
    try:
        secret = Secret.objects.filter(username=username, type='EAP').first()

        if not secret:
            return JsonResponse({
                'success': False,
                'error': f'EAP user "{username}" not found'
            }, status=404)

        return JsonResponse({
            'success': True,
            'data': {
                'username': secret.username,
                'type': secret.type
            }
        }, status=200)

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
@login_required
@require_http_methods(["POST"])
def retry_sync(request):
    """Replay all pending SyncFailure records."""
    try:
        result = peer_sync.retry_failed_syncs()
        return JsonResponse({'success': True, 'result': result})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
@login_required
@require_http_methods(["POST"])
def full_sync(request):
    """Upsert all local EAP users to every configured peer."""
    try:
        result = peer_sync.full_sync_to_peers()
        return JsonResponse({'success': True, 'result': result})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
@login_required
@require_http_methods(["POST"])
def add_sync_peer(request):
    """Add a new sync peer."""
    try:
        data = json.loads(request.body)
        url = data.get('url', '').strip().rstrip('/')
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()

        if not url or not username or not password:
            return JsonResponse({
                'success': False,
                'error': 'url, username and password are required'
            }, status=400)

        if not url.startswith(('http://', 'https://')):
            return JsonResponse({
                'success': False,
                'error': 'URL must start with http:// or https://'
            }, status=400)

        from .models import SyncPeer
        from django.db import IntegrityError as DbIntegrityError
        try:
            peer = SyncPeer.objects.create(url=url, username=username, password=password)
        except DbIntegrityError:
            return JsonResponse({'success': False, 'error': f'Peer "{url}" already exists'}, status=409)
        return JsonResponse({
            'success': True,
            'data': {'id': peer.id, 'url': peer.url, 'username': peer.username}
        }, status=201)

    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
@login_required
@require_http_methods(["DELETE"])
def delete_sync_peer(request, peer_id):
    """Delete a sync peer and its associated pending sync failures."""
    try:
        from .models import SyncPeer, SyncFailure
        peer = SyncPeer.objects.filter(id=peer_id).first()
        if not peer:
            return JsonResponse({'success': False, 'error': 'Peer not found'}, status=404)
        SyncFailure.objects.filter(peer_url=peer.url).delete()
        peer.delete()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)
