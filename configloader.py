#!/usr/bin/env python3
import os

path = os.path.dirname(os.path.realpath(__file__))
activate = os.path.join(path, 'env/bin/activate_this.py')
if os.path.exists(activate):
    with open(activate) as f:
        exec(f.read(), {'__file__': activate})

os.chdir(path)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "strongMan.settings.production")
import django
django.setup()

from collections import OrderedDict
from strongMan.apps.server_connections.models import Connection
from strongMan.apps.certificates.models.certificates import PrivateKey, Certificate, UserCertificate
from strongMan.apps.eap_secrets.models import Secret
from strongMan.apps.pools.models.pools import Pool
from strongMan.helper_apps.vici.wrapper.wrapper import ViciWrapper


def load_secrets(vici=ViciWrapper()):
    for secret in Secret.objects.all():
        vici.load_secret(secret.dict())


def load_keys(vici=ViciWrapper()):
    for key in PrivateKey.objects.all():
        vici.load_key(OrderedDict(type=key.get_algorithm_type(), data=key.der_container))


def load_certificates(vici=ViciWrapper()):
    for cert in Certificate.objects.all():
        vici.load_certificate(OrderedDict(type=cert.type, flag='None', data=cert.der_container))


def load_connections():
    for connection in Connection.objects.all():
        if connection.enabled:
            if connection.is_remote_access():
                connection.load()
            else:
                connection.start()


def load_pools(vici=ViciWrapper()):
    for pool in Pool.objects.all():
        vici.load_pool(pool.dict())


def load_credentials(vici=ViciWrapper()):
    load_secrets(vici)
    load_keys(vici)
    load_certificates(vici)


def cleanup_expired_certificates():
    from django.utils import timezone
    # Query as UserCertificate so pre_delete signals (PrivateKey cleanup) fire correctly
    expired = list(UserCertificate.objects.filter(valid_not_after__lt=timezone.now()))
    count = len(expired)
    if count > 0:
        for cert in expired:
            cert.delete()
        print(f"Cleaned up {count} expired certificate(s)")
        return True
    return False


def main():
    vici = ViciWrapper()
    cleaned = cleanup_expired_certificates()
    if cleaned:
        vici.clear_creds()
    from strongMan.apps.eap_secrets.peer_sync import retry_failed_syncs
    try:
        retry_failed_syncs()
    except Exception as e:
        print(f"Warning: retry_failed_syncs failed at startup: {e}")
    load_credentials(vici)
    load_pools(vici)
    load_connections()


if __name__ == "__main__":
    main()
