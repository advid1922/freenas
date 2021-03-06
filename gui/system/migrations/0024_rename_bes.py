# -*- coding: utf-8 -*-
# Generated by Django 1.10.8 on 2018-07-03 12:54
from __future__ import unicode_literals

from django.db import migrations
import os
import subprocess


def rename_bes(apps, schema_editor):

    # There is no reason to run that code on fresh install
    if os.environ.get('FREENAS_INSTALL', '').lower() == 'yes':
        return

    # See #36118 for more details
    cp = subprocess.run(['/usr/local/sbin/beadm', 'list', '-H'], stdout=subprocess.PIPE)
    output = cp.stdout.decode('utf8', 'ignore')
    for line in output.splitlines():
        columns = line.split()
        if ':' not in columns[0]:
            continue
        # Cannot rename current BE
        if 'N' in columns[1]:
            continue

        subprocess.run(['zfs', 'rename', f'freenas-boot/ROOT/{columns[0]}', f'freenas-boot/ROOT/{columns[0].replace(":", "-")}'])


class Migration(migrations.Migration):

    dependencies = [
        ('system', '0023_merge_20180612_2359'),
    ]

    operations = [
        migrations.RunPython(rename_bes, reverse_code=migrations.RunPython.noop),
    ]
