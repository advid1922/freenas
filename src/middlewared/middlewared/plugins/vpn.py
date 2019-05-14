import subprocess

from middlewared.service import SystemServiceService, private
from middlewared.schema import accepts, Bool, Dict, Int, IPAddr, List, Str, ValidationErrors
from middlewared.validators import Port, Range


class OpenVPN:
    CIPHERS = {}
    DIGESTS = {}

    @staticmethod
    def ciphers():
        if not OpenVPN.CIPHERS:
            proc = subprocess.Popen(
                ['openvpn', '--show-ciphers'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, stderr = proc.communicate()
            if not proc.returncode:
                OpenVPN.CIPHERS = {
                    v.split(' ')[0].strip(): ' '.join(map(str.strip, v.split(' ')[1:]))
                    for v in
                    filter(
                        lambda v: v and v.split(' ')[0].strip() == v.split(' ')[0].strip().upper(),
                        stdout.decode('utf8').split('\n')
                    )
                }

        return OpenVPN.CIPHERS

    @staticmethod
    def digests():
        if not OpenVPN.DIGESTS:
            proc = subprocess.Popen(
                ['openvpn', '--show-digests'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, stderr = proc.communicate()
            if not proc.returncode:
                OpenVPN.DIGESTS = {
                    v.split(' ')[0].strip(): ' '.join(map(str.strip, v.split(' ')[1:]))
                    for v in
                    filter(
                        lambda v: v and v.endswith('bit digest size'),
                        stdout.decode('utf8').split('\n')
                    )
                }

        return OpenVPN.DIGESTS

    @staticmethod
    async def common_validation(middleware, data, schema, mode):
        verrors = ValidationErrors()

        # TODO: Let's add checks for cert extensions as well please
        if not await middleware.call(
            'certificateauthority.query', [
                ['id', '=', data['root_ca']],
                ['revoked', '=', False]
            ]
        ):
            verrors.add(
                f'{schema}.root_ca',
                'Please provide a valid id for Root Certificate Authority which exists on the system '
                'and hasn\'t been revoked.'
            )

        if not await middleware.call(
            'certificate.query', [
                ['id', '=', data[f'{mode}_certificate']],
                ['revoked', '=', False]
            ]
        ):
            verrors.add(
                f'{schema}.certificate',
                f'Please provide a valid id for {mode.capitalize()} certificate which exists on '
                'the system and hasn\'t been revoked.'
            )

        other = 'openvpn.server' if mode == 'client' else 'openvpn.client'
        other_config = await middleware.call(
            f'{other}.config'
        )

        if (
            await middleware.call(
                'service.started',
                other.replace('.', '_')
            ) and data['port'] == other_config['port'] and (
                not other_config['nobind'] or not data['nobind']
            )
        ):
            verrors.add(
                f'{schema}.nobind',
                'Please enable this to concurrently run OpenVPN Server/Client on the same local port.'
            )

        return verrors


class OpenVPNServerService(SystemServiceService):

    class Config:
        namespace = 'openvpn.server'
        service = 'openvpn_server'
        service_model = 'openvpnserver'
        service_verb = 'restart'

    @private
    async def validate(self, data, schema_name):
        # Before validating, if `null` is provided for `root_ca`/`server_certificate`,
        # let's setup the PKI first.

        verrors = await OpenVPN.common_validation(
            self.middleware, data, schema_name, 'server'
        )

        verrors.check()

    @accepts(
        Dict(
            'openvpn_server_update',
            Bool('nobind'),
            Bool('tls_crypt_auth_enabled'),
            Int('netmask', validators=[Range(min=0, max=32)]),
            Int('server_certificate', null=True),
            Int('compression', null=True),
            Int('port', validators=[Port()]),
            Int('root_ca', null=True),
            IPAddr('server'),
            Str('additional_parameters'),
            Str('authentication_algorithm', enum=OpenVPN.digests(), null=True),
            Str('cipher', null=True, enum=OpenVPN.ciphers()),
            Str('compression', null=True, enum=['LZO', 'LZ4']),
            Str('device_type', enum=['TUN', 'TAP']),
            Str('protocol', enum=['UDP', 'TCP']),
            Str('tls_crypt_auth', null=True),
            Str('topology', null=True, enum=['NET30', 'P2P', 'SUBNET']),
            update=True
        )
    )
    async def do_update(self, data):
        old_config = await self.config()
        config = old_config.copy()

        config.update(data)

        await self.validate(config, 'openvpn_server_update')

        await self._update_service(old_config, config)

        return await self.config()


class OpenVPNClientService(SystemServiceService):

    class Config:
        namespace = 'openvpn.client'
        service = 'openvpn_client'
        service_model = 'openvpnclient'
        service_verb = 'restart'

    @private
    async def validate(self, data, schema_name):
        verrors = await OpenVPN.common_validation(
            self.middleware, data, schema_name, 'client'
        )

        if not data.get('remote'):
            verrors.add(
                f'{schema_name}.remote',
                'This field is required.'
            )

        verrors.check()

    @accepts(
        Dict(
            'openvpn_client_update',
            Bool('nobind'),
            Bool('tls_crypt_auth_enabled'),
            Int('client_certificate', null=True),
            Int('compression', null=True),
            Int('root_ca', null=True),
            Int('port', validators=[Port()]),
            Int('remote_port', validators=[Port()]),
            Str('additional_parameters'),
            Str('authentication_algorithm', enum=OpenVPN.digests(), null=True),
            Str('cipher', null=True, enum=OpenVPN.ciphers()),
            Str('compression', null=True, enum=['LZO', 'LZ4']),
            Str('device_type', enum=['TUN', 'TAP']),
            Str('protocol', enum=['UDP', 'TCP']),
            Str('remote'),
            Str('tls_crypt_auth', null=True),
            update=True
        )
    )
    async def do_update(self, data):
        old_config = await self.config()
        config = old_config.copy()

        config.update(data)

        await self.validate(config, 'openvpn_client_update')

        await self._update_service(old_config, config)

        return await self.config()
