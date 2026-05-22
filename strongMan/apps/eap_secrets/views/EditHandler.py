import logging
from collections import OrderedDict

from django.contrib import messages
from django.shortcuts import redirect
from django.urls import reverse
from django.shortcuts import render
from django.db.models import ProtectedError

from ..forms import AddOrEditForm
from ..models import Secret
from .. import peer_sync
from strongMan.helper_apps.vici.wrapper.wrapper import ViciWrapper
from strongMan.helper_apps.vici.wrapper.exception import ViciException

logger = logging.getLogger(__name__)


class EditHandler(object):
    def __init__(self, request, secret):
        self.request = request
        self.secret = secret

    def _render_edit(self, form=AddOrEditForm()):
        return render(self.request, 'eap_secrets/edit.html', {"form": form})

    def delete_secret(self):
        saved_pk = self.secret.pk
        try:
            username = self.secret.username
            self.secret.delete()
            self.reload_secrets()
            # Local DB + vici consistent — now notify peers
            peer_sync.push_delete(username)
            messages.add_message(self.request, messages.SUCCESS, 'Successfully deleted EAP Secret')
        except ProtectedError:
            messages.add_message(self.request, messages.ERROR,
                                 'Secret not deleted! Secret is referenced by a Connection')
        except ViciException as e:
            # Django clears pk after delete(); restore it so save() re-inserts the original row
            self.secret.pk = saved_pk
            self.secret.save(force_insert=True)
            messages.add_message(self.request, messages.ERROR, str(e))
        return redirect(reverse("eap_secrets:overview"))

    def update_secret(self):
        form = AddOrEditForm(self.request.POST)
        if not form.is_valid():
            return self._render_edit(form)
        username = self.secret.username
        old_password = self.secret.password
        old_salt = self.secret.salt
        new_password = form.my_password
        if not new_password:
            messages.add_message(self.request, messages.ERROR, 'Password is required')
            return self._render_edit(form)
        try:
            self.secret.password = form.my_salted_password
            self.secret.salt = form.my_salt
            self.secret.save()
            self.reload_secrets()
            # Local DB + vici consistent — now notify peers (sequential delete+upsert per peer)
            peer_sync.push_update(username, new_password)
            messages.add_message(self.request, messages.SUCCESS, 'Successfully updated EAP Secret')
        except ViciException as e:
            self.secret.password = old_password
            self.secret.salt = old_salt
            self.secret.save()
            messages.add_message(self.request, messages.ERROR, str(e))
            return render(self.request, 'eap_secrets/edit.html', {"form": form})
        return redirect(reverse("eap_secrets:overview"))

    def reload_secrets(self):
        from strongMan.apps.certificates.models.certificates import PrivateKey, Certificate
        vici = ViciWrapper()
        vici.clear_creds()
        for secret in Secret.objects.all():
            vici.load_secret(secret.dict())
        for key in PrivateKey.objects.all():
            try:
                vici.load_key(OrderedDict(type=key.get_algorithm_type(), data=key.der_container))
            except Exception as e:
                logger.warning('reload_secrets: failed to load key: %s', e)
        for cert in Certificate.objects.all():
            try:
                vici.load_certificate(OrderedDict(type=cert.type, flag='None', data=cert.der_container))
            except Exception as e:
                logger.warning('reload_secrets: failed to load certificate: %s', e)

    def handle(self):
        if self.request.method == "GET":
            form = AddOrEditForm()
            form.my_username = self.secret.username
            form.my_salted_password = self.secret.password
            return self._render_edit(form)
        elif self.request.method == "POST":
            if "remove_secret" in self.request.POST:
                return self.delete_secret()
            else:
                return self.update_secret()
