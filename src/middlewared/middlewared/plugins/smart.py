import functools
import re
from datetime import datetime
from itertools import chain

from middlewared.common.camcontrol import camcontrol_list
from middlewared.common.smart.smartctl import get_smartctl_args
from middlewared.schema import accepts, Bool, Cron, Dict, Int, List, Patch, Str
from middlewared.validators import Email, Range, Unique
from middlewared.service import CRUDService, filterable, filter_list, private, SystemServiceService, ValidationErrors
from middlewared.utils import run
from middlewared.utils.asyncio_ import asyncio_map, call_later


async def annotate_disk_smart_tests(devices, disk):
    if disk["disk"] is None or disk["disk"].startswith("nvd"):
        return None

    device = devices.get(disk["disk"])
    if device:
        args = await get_smartctl_args(disk["disk"], device)
        p = await run(["smartctl", "-l", "selftest"] + args, check=False, encoding="utf8")
        tests = parse_smart_selftest_results(p.stdout)
        if tests is not None:
            return dict(tests=tests, **disk)


def parse_smart_selftest_results(stdout):
    tests = []

    # ataprint.cpp
    if "LBA_of_first_error" in stdout:
        for line in stdout.split("\n"):
            if not line.startswith("#"):
                continue

            test = {
                "num": int(line[1:3].strip()),
                "description": line[5:24].strip(),
                "status_verbose": line[25:54].strip(),
                "remaining": int(line[55:57]) / 100,
                "lifetime": int(line[60:68].strip()),
                "lba_of_first_error": line[77:].strip(),
            }

            if test["status_verbose"] == "Completed without error":
                test["status"] = "SUCCESS"
            elif test["status_verbose"] == "Self-test routine in progress":
                test["status"] = "RUNNING"
            else:
                test["status"] = "FAILED"

            if test["lba_of_first_error"] == "-":
                test["lba_of_first_error"] = None

            tests.append(test)

        return tests

    # scsiprint.cpp
    if "LBA_first_err" in stdout:
        for line in stdout.split("\n"):
            if not line.startswith("#"):
                continue

            test = {
                "num": int(line[1:3].strip()),
                "description": line[5:20].strip(),
                "status_verbose": line[23:48].strip(),
                "segment_number": line[49:52].strip(),
                "lifetime": line[55:60].strip(),
                "lba_of_first_error": line[60:78].strip(),
            }

            if test["status_verbose"] == "Completed":
                test["status"] = "SUCCESS"
            elif test["status_verbose"] == "Self test in progress ...":
                test["status"] = "RUNNING"
            else:
                test["status"] = "FAILED"

            if test["segment_number"] == "-":
                test["segment_number"] = None
            else:
                test["segment_number"] = int(test["segment_number"])

            if test["lifetime"] == "NOW":
                test["lifetime"] = None
            else:
                test["lifetime"] = int(test["lifetime"])

            if test["lba_of_first_error"] == "-":
                test["lba_of_first_error"] = None

            tests.append(test)

        return tests


class SMARTTestService(CRUDService):

    class Config:
        datastore = 'tasks.smarttest'
        datastore_extend = 'smart.test.smart_test_extend'
        datastore_prefix = 'smarttest_'
        namespace = 'smart.test'

    @private
    async def smart_test_extend(self, data):
        disks = data.pop('disks')
        data['disks'] = [disk['disk_identifier'] for disk in disks]
        test_type = {
            'L': 'LONG',
            'S': 'SHORT',
            'C': 'CONVEYANCE',
            'O': 'OFFLINE',
        }
        data['type'] = test_type[data.pop('type')]
        Cron.convert_db_format_to_schedule(data)
        return data

    @private
    async def validate_data(self, data, schema):
        verrors = ValidationErrors()

        smart_tests = await self.query(filters=[('type', '=', data['type'])])
        configured_disks = [d for test in smart_tests for d in test['disks']]
        disks_dict = {disk['identifier']: disk['name'] for disk in (await self.middleware.call('disk.query'))}

        disks = data.get('disks')
        used_disks = []
        invalid_disks = []
        for disk in disks:
            if disk in configured_disks:
                used_disks.append(disks_dict[disk])
            if disk not in disks_dict.keys():
                invalid_disks.append(disk)

        if used_disks:
            verrors.add(
                f'{schema}.disks',
                f'The following disks already have tests for this type: {", ".join(used_disks)}'
            )

        if invalid_disks:
            verrors.add(
                f'{schema}.disks',
                f'The following disks are invalid: {", ".join(invalid_disks)}'
            )

        return verrors

    @accepts(
        Dict(
            'smart_task_create',
            Cron(
                'schedule',
                exclude=['minute']
            ),
            Str('desc'),
            Bool('all_disks', default=False),
            List('disks', items=[Str('disk')], default=[]),
            Str('type', enum=['LONG', 'SHORT', 'CONVEYANCE', 'OFFLINE'], required=True),
            register=True
        )
    )
    async def do_create(self, data):
        """
        Create a SMART Test Task.

        `disks` is a list of valid disks which should be monitored in this task.

        `type` is specified to represent the type of SMART test to be executed.

        `all_disks` when enabled sets the task to cover all disks in which case `disks` is not required.

        .. examples(websocket)::

          Create a SMART Test Task which executes after every 30 minutes.

            :::javascript
            {
                "id": "6841f242-840a-11e6-a437-00e04d680384",
                "msg": "method",
                "method": "smart.test.create",
                "params": [{
                    "schedule": {
                        "minute": "30",
                        "hour": "*",
                        "dom": "*",
                        "month": "*",
                        "dow": "*"
                    },
                    "all_disks": true,
                    "type": "OFFLINE",
                    "disks": []
                }]
            }
        """
        data['type'] = data.pop('type')[0]
        verrors = await self.validate_data(data, 'smart_test_create')

        if data['all_disks']:
            if data.get('disks'):
                verrors.add(
                    'smart_test_create.disks',
                    'This test is already enabled for all disks'
                )
        else:
            if not data.get('disks'):
                verrors.add(
                    'smart_test_create.disks',
                    'This field is required'
                )

        if verrors:
            raise verrors

        Cron.convert_schedule_to_db_format(data)

        data['id'] = await self.middleware.call(
            'datastore.insert',
            self._config.datastore,
            data,
            {'prefix': self._config.datastore_prefix}
        )

        await self._service_change('smartd', 'restart')

        return data

    @accepts(
        Int('id', validators=[Range(min=1)]),
        Patch('smart_task_create', 'smart_task_update', ('attr', {'update': True}))
    )
    async def do_update(self, id, data):
        """
        Update SMART Test Task of `id`.
        """
        old = await self.query(filters=[('id', '=', id)], options={'get': True})
        new = old.copy()
        new.update(data)

        new['type'] = new.pop('type')[0]
        old['type'] = old.pop('type')[0]
        new_disks = [disk for disk in new['disks'] if disk not in old['disks']]
        deleted_disks = [disk for disk in old['disks'] if disk not in new['disks']]
        if old['type'] == new['type']:
            new['disks'] = new_disks
        verrors = await self.validate_data(new, 'smart_test_update')

        new['disks'] = [disk for disk in chain(new_disks, old['disks']) if disk not in deleted_disks]

        if new['all_disks']:
            if new.get('disks'):
                verrors.add(
                    'smart_test_update.disks',
                    'This test is already enabled for all disks'
                )
        else:
            if not new.get('disks'):
                verrors.add(
                    'smart_test_update.disks',
                    'This field is required'
                )

        if verrors:
            raise verrors

        Cron.convert_schedule_to_db_format(new)

        await self.middleware.call(
            'datastore.update',
            self._config.datastore,
            id,
            new,
            {'prefix': self._config.datastore_prefix}
        )

        await self._service_change('smartd', 'restart')

        return await self.query(filters=[('id', '=', id)], options={'get': True})

    @accepts(
        Int('id')
    )
    async def do_delete(self, id):
        """
        Delete SMART Test Task of `id`.
        """
        response = await self.middleware.call(
            'datastore.delete',
            self._config.datastore,
            id
        )

        await self._service_change('smartd', 'restart')

        return response

    @private
    async def manual_test_alert(self, disk, smartd_pid, ids):
        results = await self.middleware.call(
            'smart.test.results', [
                ['disk', '=', disk],
            ]
        )
        alert = {
            'title': f'Manual SMART Test Run for {disk}',
            'category': 'STORAGE',
            'level': 'INFO'
        }
        if not results or not results[0]['tests']:
            await self.middleware.call(
                'alertservice.send_alerts',
                ids, {
                    'text': f'{alert["title"]}\n' + 'Failed to retrieve results.',
                    **alert
                }
            )
        else:
            result = results[0]['tests'][0]
            if result['status'] == 'RUNNING':
                current_smartd_pid = await self.middleware.call('smart.smartd_pid')
                if current_smartd_pid == smartd_pid:
                    call_later(
                        60,
                        self.manual_test_alert, [disk, smartd_pid, id]
                    )
            else:
                await self.middleware.call(
                    'alertservice.send_alerts',
                    ids, {
                        'text': f'{alert["title"]}\n' + '\n'.join(
                            f'{k}: {v}' for k, v in result.items()
                        ),
                        **alert
                    }
                )

    @accepts(
        List(
            'disks', items=[
                Dict(
                    'disk_run',
                    List('alert_service_ids', default=[], items=[Int('alert_service_id')]),
                    Str('identifier', required=True),
                    Str('mode', enum=['FOREGROUND', 'BACKGROUND'], default='BACKGROUND'),
                    Str('type', enum=['LONG', 'SHORT', 'CONVEYANCE', 'OFFLINE'], required=True),
                )
            ]
        )
    )
    async def manual_test(self, disks):
        """
        Run manual SMART tests for `disks`.

        `type` indicates what type of SMART test will be ran and must be specified.
        """
        verrors = ValidationErrors()
        if not disks:
            verrors.add(
                'manual_test.disks',
                'Please specify at least one disk.'
            )
        else:
            test_disks_list = []
            disks_data = await self.middleware.call('disk.query')
            devices = await camcontrol_list()

            for disk in disks:
                for d in disks_data:
                    if disk['identifier'] == d['identifier']:
                        current_disk = d
                        test_disks_list.append({
                            'disk': current_disk['name'],
                            **disk
                        })
                        break
                else:
                    verrors.add(
                        'manual_test.disks.identifier',
                        f'{disk["identifier"]} is not valid. Please provide a valid disk identifier.'
                    )
                    continue

                if disk['alert_service_ids'] and not set(
                    disk['alert_service_ids']
                ).issubset({
                    a['id'] for a in (await self.middleware.call('alertservice.query'))
                }):
                    verrors.add(
                        'manual_test.disks.alert_service_ids',
                        f'Please provide a valid list of alert service id\'s for {disk["identifier"]}'
                    )

                if current_disk['name'] is None or current_disk['name'].startswith('nvd'):
                    verrors.add(
                        'manual_test.disks.identifier',
                        f'Test cannot be performed for {disk["identifier"]} disk. Failed to retrieve name.'
                    )

                device = devices.get(current_disk['name'])
                if not device:
                    verrors.add(
                        'manual_test.disks.identifier',
                        f'Test cannot be performed for {disk["identifier"]}. Unable to retrieve disk details.'
                    )

        verrors.check()

        smartd_pid = await self.middleware.call('smart.smartd_pid')

        return list(
            await asyncio_map(functools.partial(self.__manual_test, devices, smartd_pid), test_disks_list, 16)
        )

    async def __manual_test(self, devices, smartd_pid, disk):
        device = devices.get(disk['disk'])
        args = await get_smartctl_args(disk['disk'], device)

        proc = await run(
            list(
                filter(bool, ['smartctl', '-t', disk['type'].lower(), '-C' if disk['mode'] == 'FOREGROUND' else None])
            ) + args,
            check=False, encoding='utf8'
        )

        output = {}
        if proc.returncode:
            output['error'] = proc.stderr
            self.middleware.logger.debug(
                f'Self test for {disk["disk"]} failed with {proc.returncode} return code.'
            )
        else:
            time_details = re.findall('test will complete after(.*)', proc.stdout, re.IGNORECASE)
            if not time_details:
                output['error'] = f'Failed to parse smartctl self test details for {disk["identifier"]}.'
            else:
                output['Expected Result Time'] = time_details[0].strip()
                if disk['alert_service_ids']:
                    call_later(
                        60,
                        self.manual_test_alert, [disk['disk'], smartd_pid, disk['alert_service_ids']]
                    )

        return {
            'disk': disk['disk'],
            'identifier': disk['identifier'],
            **output
        }

    @filterable
    async def results(self, filters, options):
        """
        Get disk(s) S.M.A.R.T. test(s) results.

        .. examples(websocket)::

          Get all disks tests results

            :::javascript
            {
                "id": "6841f242-840a-11e6-a437-00e04d680384",
                "msg": "method",
                "method": "smart.test.results",
                "params": []
            }

            returns

            :::javascript

            [
              # ATA disk
              {
                "disk": "ada0",
                "tests": [
                  {
                    "num": 1,
                    "description": "Short offline",
                    "status": "SUCCESS",
                    "status_verbose": "Completed without error",
                    "remaining": 0.0,
                    "lifetime": 16590,
                    "lba_of_first_error": None,
                  }
                ]
              },
              # SCSI disk
              {
                "disk": "ada1",
                "tests": [
                  {
                    "num": 1,
                    "description": "Background long",
                    "status": "FAILED",
                    "status_verbose": "Completed, segment failed",
                    "segment_number": None,
                    "lifetime": 3943,
                    "lba_of_first_error": None,
                  }
                ]
              },
            ]

          Get specific disk test results

            :::javascript
            {
                "id": "6841f242-840a-11e6-a437-00e04d680384",
                "msg": "method",
                "method": "smart.test.results",
                "params": [
                  [["disk", "=", "ada0"]],
                  {"get": true}
                ]
            }

            returns

            :::javascript

            {
              "disk": "ada0",
              "tests": [
                {
                  "num": 1,
                  "description": "Short offline",
                  "status": "SUCCESS",
                  "status_verbose": "Completed without error",
                  "remaining": 0.0,
                  "lifetime": 16590,
                  "lba_of_first_error": None,
                }
              ]
            }
        """

        get = (options or {}).pop("get", False)

        disks = filter_list(
            [{"disk": disk["name"]} for disk in await self.middleware.call("disk.query")],
            filters,
            options,
        )

        devices = await camcontrol_list()
        return filter_list(
            list(filter(None, await asyncio_map(functools.partial(annotate_disk_smart_tests, devices), disks, 16))),
            [],
            {"get": get},
        )


class SmartService(SystemServiceService):

    class Config:
        service = "smartd"
        service_model = "smart"
        datastore_extend = "smart.smart_extend"
        datastore_prefix = "smart_"

    @private
    async def smart_extend(self, smart):
        smart["powermode"] = smart["powermode"].upper()
        smart["email"] = smart["email"].split(",")
        return smart

    @accepts(Dict(
        'smart_update',
        Int('interval'),
        Str('powermode', enum=['NEVER', 'SLEEP', 'STANDBY', 'IDLE']),
        Int('difference'),
        Int('informational'),
        Int('critical'),
        List('email', validators=[Unique()], items=[Str('email', validators=[Email()])]),
        update=True
    ))
    async def do_update(self, data):
        """
        Update SMART Service Configuration.

        `interval` is an integer value in minutes which defines how often smartd activates to check if any tests
        are configured to run.

        `critical`, `informational` and `difference` are integer values on which alerts for SMART are configured if
        the disks temperature crosses the assigned threshold for each respective attribute. They default to 0 which
        indicates they are disabled.

        Email of log level LOG_CRIT is issued when disk temperature crosses `critical`.

        Email of log level LOG_INFO is issued when disk temperature crosses `informational`.

        If temperature of a disk changes by `difference` degree Celsius since the last report, SMART reports this.

        `email` is a list of valid emails to receive SMART alerts.
        """
        old = await self.config()

        new = old.copy()
        new.update(data)

        new["powermode"] = new["powermode"].lower()
        new["email"] = ",".join([email.strip() for email in new["email"]])

        await self._update_service(old, new)

        if new["powermode"] != old["powermode"]:
            await self.middleware.call("service.restart", "collectd", {"onetime": False})

        await self.smart_extend(new)

        return new

    @private
    async def smartd_pid(self):
        """
        Returns Process PID of smartd daemon. If it is not running, None is returned.
        """
        proc = await run(
            ['pgrep', '-x', 'smartd'],
            check=False, encoding='utf8'
        )
        if not proc.returncode:
            return int(proc.stdout.split()[0])
