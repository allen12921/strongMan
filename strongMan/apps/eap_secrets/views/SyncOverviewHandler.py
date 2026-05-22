from django.shortcuts import render

from ..models import SyncFailure, SyncPeer


class SyncOverviewHandler:
    def __init__(self, request):
        self.request = request

    def handle(self):
        peers_qs = list(SyncPeer.objects.all())
        failures = list(SyncFailure.objects.all())

        failure_counts = {}
        for f in failures:
            failure_counts[f.peer_url] = failure_counts.get(f.peer_url, 0) + 1

        peers = [
            {
                'id': p.id,
                'url': p.url,
                'username': p.username,
                'pending': failure_counts.get(p.url, 0),
            }
            for p in peers_qs
        ]

        return render(self.request, 'eap_secrets/sync_overview.html', {
            'peers': peers,
            'failures': failures,
            'total_pending': len(failures),
        })
