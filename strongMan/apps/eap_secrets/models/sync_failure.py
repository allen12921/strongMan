from django.db import models

from strongMan.helper_apps.encryption import fields


class SyncFailure(models.Model):
    peer_url = models.TextField()
    action = models.CharField(max_length=10)  # 'create' | 'update' | 'delete'
    username = models.TextField()
    password = fields.EncryptedTextField(blank=True)  # plaintext, only for 'create'
    created_at = models.DateTimeField(auto_now_add=True)
    last_error = models.TextField(blank=True)

    class Meta:
        ordering = ['-created_at']
