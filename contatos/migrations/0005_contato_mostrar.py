# Generated by Django 4.0.4 on 2022-04-17 19:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('contatos', '0004_alter_contato_data_criacao'),
    ]

    operations = [
        migrations.AddField(
            model_name='contato',
            name='mostrar',
            field=models.BooleanField(default=True),
        ),
    ]
