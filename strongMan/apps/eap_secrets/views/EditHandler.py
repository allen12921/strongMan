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
            ViciWrapper().unload_secret(username)
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
            ViciWrapper().unload_secret(username)
            ViciWrapper().load_secret(self.secret.dict())
            peer_sync.push_update(username, new_password)
            messages.add_message(self.request, messages.SUCCESS, 'Successfully updated EAP Secret')
        except ViciException as e:
            self.secret.password = old_password
            self.secret.salt = old_salt
            self.secret.save()
            try:
                ViciWrapper().load_secret(self.secret.dict())
            except Exception:
                pass
            messages.add_message(self.request, messages.ERROR, str(e))
            return render(self.request, 'eap_secrets/edit.html', {"form": form})
        return redirect(reverse("eap_secrets:overview"))

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
