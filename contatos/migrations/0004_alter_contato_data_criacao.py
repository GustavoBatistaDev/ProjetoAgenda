# Generated by Django 4.0.4 on 2022-04-17 18:47

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('contatos', '0003_alter_contato_descricao'),
    ]

    operations = [
        migrations.AlterField(
            model_name='contato',
            name='data_criacao',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
    ]
