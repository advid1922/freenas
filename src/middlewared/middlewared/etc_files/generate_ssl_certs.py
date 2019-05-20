import os


def write_certificates(certs):
    for cert in certs:
        if not os.path.exists(cert['root_path']):
            os.mkdir(cert['root_path'], 0o755)

        if cert['chain_list']:
            with open(cert['certificate_path'], 'w') as f:
                for i in cert['chain_list']:
                    f.write(i)

        if cert['privatekey']:
            with open(cert['privatekey_path'], 'w') as f:
                f.write(cert['privatekey'])
            os.chmod(cert['privatekey_path'], 0o400)

        if cert['type'] & 0x20 and cert['CSR']:
            with open(cert['csr_path'], 'w') as f:
                f.write(cert['CSR'])


def get_issuer_ca(ca_id, middleware):
    ca = middleware.call_sync(
        'certificateauthority.query',
        [['id', '=', ca_id]],
        {'get': True}
    )

    if ca['signedby'] and ca['revoked']:
        return get_issuer_ca(ca['signedby']['id'], middleware)
    else:
        return ca


def write_crls(cas, middleware):
    for ca in cas:
        issuer_ca = get_issuer_ca(ca['id'], middleware)
        crl = middleware.call_sync(
            'cryptokey.generate_crl',
            issuer_ca, list(
                filter(
                    lambda cert: cert['revoked'],
                    middleware.call_sync(
                        'certificateauthority.get_ca_chain', ca['id']
                    )
                )
            )
        )
        if crl:
            with open(issuer_ca['crl_path'], 'w') as f:
                f.write(crl)


def render(service, middleware):
    certs = middleware.call_sync('certificate.query')
    cas = middleware.call_sync('certificateauthority.query')
    certs.extend(cas)

    write_certificates(certs)

    write_crls(
        filter(
            lambda ca: ca['revoked_certs'],
            cas
        ), middleware
    )
