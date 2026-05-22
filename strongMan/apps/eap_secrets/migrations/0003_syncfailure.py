from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('eap_secrets', '0002_update_encrypted_fields'),
    ]

    operations = [
        migrations.CreateModel(
            name='SyncFailure',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('peer_url', models.TextField()),
                ('action', models.CharField(max_length=10)),
                ('username', models.TextField()),
                ('password', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('last_error', models.TextField(blank=True)),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
