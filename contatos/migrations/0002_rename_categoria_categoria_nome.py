# Generated by Django 4.0.4 on 2022-04-17 18:17

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('contatos', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='categoria',
            old_name='categoria',
            new_name='nome',
        ),
    ]
