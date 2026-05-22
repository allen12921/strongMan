from django.db import models

from strongMan.helper_apps.encryption import fields


class SyncPeer(models.Model):
    url = models.TextField(unique=True)
    username = models.TextField()
    password = fields.EncryptedTextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['url']
