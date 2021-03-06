# -*- coding: utf-8 -*-
# Generated by Django 1.10.8 on 2018-08-20 11:50
from __future__ import unicode_literals

from django.db import migrations, models


def preserve_order(apps, schema_editor):
    Device = apps.get_model('vm', 'Device')
    for device in Device.objects.order_by('id'):
        device.order = device.id
        device.save()


class Migration(migrations.Migration):

    dependencies = [
        ('vm', '0006_auto_20171226_1820'),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='order',
            field=models.IntegerField(editable=False, null=True),
        ),
        migrations.RunPython(preserve_order, reverse_code=migrations.RunPython.noop),
    ]
