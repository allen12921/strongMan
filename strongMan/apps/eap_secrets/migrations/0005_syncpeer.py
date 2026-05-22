from django.db import migrations, models

import strongMan.helper_apps.encryption.fields


class Migration(migrations.Migration):

    dependencies = [
        ('eap_secrets', '0004_syncfailure_encrypt_password'),
    ]

    operations = [
        migrations.CreateModel(
            name='SyncPeer',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('url', models.TextField()),
                ('username', models.TextField()),
                ('password', strongMan.helper_apps.encryption.fields.EncryptedTextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'ordering': ['url'],
            },
        ),
    ]
