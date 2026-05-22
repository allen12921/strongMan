from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('eap_secrets', '0005_syncpeer'),
    ]

    operations = [
        migrations.AlterField(
            model_name='syncpeer',
            name='url',
            field=models.TextField(unique=True),
        ),
    ]
