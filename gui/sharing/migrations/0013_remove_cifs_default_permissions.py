# -*- coding: utf-8 -*-
# Generated by Django 1.10.8 on 2018-04-13 04:58
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('sharing', '0012_merge_20180212_1718'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='cifs_share',
            name='cifs_default_permissions',
        ),
    ]