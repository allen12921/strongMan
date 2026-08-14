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
from oscrypto import keys as oscrypto_keys
from strongMan.apps.server_connections.models import Connection
from strongMan.apps.certificates.models.certificates import PrivateKey, Certificate, UserCertificate, ViciCertificate
from strongMan.apps.eap_secrets.models import Secret
from strongMan.apps.pools.models.pools import Pool
from strongMan.helper_apps.vici.wrapper.wrapper import ViciWrapper

# Default swanctl credential directories holding X.509 certs (see swanctl.conf(5)):
# x509 = end-entity certs, x509ca = CA certs, x509aa = attribute-authority certs.
# x509ac (attribute certificates) is a different ASN.1 format this codebase has no
# parser for and is intentionally not scanned. Used only for the best-effort expiry
# check below, not for loading itself.
SWANCTL_CERT_DIRS = ("/etc/swanctl/x509", "/etc/swanctl/x509ca", "/etc/swanctl/x509aa")


def load_secrets(vici=ViciWrapper()):
    for secret in Secret.objects.all():
        vici.load_secret(secret.dict())


def load_keys(vici=ViciWrapper()):
    for key in PrivateKey.objects.all():
        vici.load_key(OrderedDict(type=key.get_algorithm_type(), data=key.der_container))


def load_certificates(vici=ViciWrapper()):
    from django.utils import timezone
    # Defense in depth: cleanup_expired_certificates() should have already
    # deleted expired rows, but never push an expired cert into charon from
    # here regardless of whether cleanup ran first.
    for cert in Certificate.objects.filter(valid_not_after__gte=timezone.now()):
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
    # Certificate is the base model; UserCertificate/ViciCertificate are subclasses
    # (Django multi-table inheritance). Querying only UserCertificate misses expired
    # ViciCertificate rows (certs mirrored in from vici), which then keep getting
    # pushed back into charon by load_certificates() on every restart.
    expired_ids = list(
        Certificate.objects.filter(valid_not_after__lt=timezone.now()).values_list("id", flat=True)
    )
    count = 0
    for cert_id in expired_ids:
        # Delete through the most specific subclass so type-specific pre_delete
        # cleanup (e.g. UserCertificate's private key handling) still runs.
        cert = (
            UserCertificate.objects.filter(pk=cert_id).first()
            or ViciCertificate.objects.filter(pk=cert_id).first()
            or Certificate.objects.filter(pk=cert_id).first()
        )
        if cert is None:
            continue
        cert.delete()
        count += 1
    if count > 0:
        print(f"Cleaned up {count} expired certificate(s)")
        return True
    return False


def _expired_swanctl_cert_files(cert_dirs=SWANCTL_CERT_DIRS):
    """Best-effort scan of the on-disk swanctl cert directories for expired
    certificates. There is no vici/swanctl command to selectively exclude a
    single expired file from `swanctl --load-creds` (it loads the whole
    directory), so this can only warn loudly, not prevent the reload below.

    Reads validity via oscrypto directly rather than X509Reader: the latter's
    parse() rejects non-RSA/EC keys (e.g. Ed25519, DSA) before validity can be
    read, which would silently hide expired certs using those algorithms.
    """
    from django.utils import timezone

    now = timezone.now()
    expired = []
    for cert_dir in cert_dirs:
        try:
            names = sorted(os.listdir(cert_dir))
        except OSError:
            continue  # missing/unreadable directory -- this is best-effort only
        for name in names:
            file_path = os.path.join(cert_dir, name)
            try:
                with open(file_path, 'rb') as f:
                    asn1_cert = oscrypto_keys.parse_certificate(f.read())
                not_after = asn1_cert.native["tbs_certificate"]["validity"]["not_after"]
                if not_after < now:
                    expired.append((file_path, not_after))
            except Exception:
                continue  # not a cert we can parse (e.g. a CRL or unrelated file)
    return expired


def main():
    import subprocess
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
    if cleaned:
        # Restore filesystem-based credentials (e.g. private key from /etc/swanctl/conf.d/)
        # that were evicted by clear_creds(). The vici protocol has no "reload from filesystem"
        # command; only swanctl can do this by reading /etc/swanctl/* and calling load-key/load-cert.
        # This can reintroduce an expired cert if the on-disk file itself hasn't been renewed yet
        # (e.g. a failed cert renewal) -- warn loudly since swanctl gives no way to exclude just
        # that file from the reload.
        try:
            for file_path, not_after in _expired_swanctl_cert_files():
                print(f"Warning: {file_path} is expired (not_after={not_after}); "
                      f"swanctl --load-creds will reload it into charon anyway")
        except Exception as e:
            print(f"Warning: expired-cert scan failed, continuing anyway: {e}")
        try:
            result = subprocess.run(['swanctl', '--load-creds'], capture_output=True, check=False)
            if result.returncode != 0:
                print(f"Warning: swanctl --load-creds failed: {result.stderr.decode()}")
        except FileNotFoundError:
            print("Warning: swanctl not found; file-based private key may need a daemon restart to reload")
    load_pools(vici)
    load_connections()


if __name__ == "__main__":
    main()
