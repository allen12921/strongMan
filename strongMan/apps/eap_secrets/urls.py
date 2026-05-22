from django.urls import re_path

from . import views
from . import api_views

app_name = 'eap_secrets'
urlpatterns = [
    # API endpoints
    re_path(r'api/sync/retry$', api_views.retry_sync, name='api_sync_retry'),
    re_path(r'api/sync/full$', api_views.full_sync, name='api_sync_full'),
    re_path(r'api/peers/add$', api_views.add_sync_peer, name='api_peers_add'),
    re_path(r'api/peers/(?P<peer_id>\d+)/delete$', api_views.delete_sync_peer, name='api_peers_delete'),
    re_path(r'api/$', api_views.list_eap_users, name='api_list'),
    re_path(r'api/create$', api_views.create_eap_user, name='api_create'),
    re_path(r'api/(?P<username>[0-9a-zA-Z_\-]+)$', api_views.get_eap_user, name='api_get'),
    re_path(r'api/(?P<username>[0-9a-zA-Z_\-]+)/delete$', api_views.delete_eap_user, name='api_delete'),

    # Web UI endpoints
    re_path(r'sync/$', views.sync_overview, name='sync_overview'),
    re_path(r'add$', views.add, name='add'),
    re_path(r'^(?P<secret_name>[0-9a-zA-Z_\-]+)$', views.edit, name='edit'),
    re_path(r'$', views.overview, name='overview'),
]
