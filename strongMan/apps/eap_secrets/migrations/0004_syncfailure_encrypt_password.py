from django.db import migrations

import strongMan.helper_apps.encryption.fields


class Migration(migrations.Migration):

    dependencies = [
        ('eap_secrets', '0003_syncfailure'),
    ]

    operations = [
        migrations.AlterField(
            model_name='syncfailure',
            name='password',
            field=strongMan.helper_apps.encryption.fields.EncryptedTextField(blank=True),
        ),
    ]
