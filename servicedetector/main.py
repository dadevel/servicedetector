#!/usr/bin/env python3
from typing import Any

from pathlib import PurePath
from argparse import ArgumentParser, Namespace
import json
import logging
import sys

from impacket.dcerpc.v5 import lsad, lsat
from impacket.dcerpc.v5.transport import DCERPCTransportFactory, DCERPC_v5, SMBTransport
from impacket.dcerpc.v5.dtypes import NULL, MAXIMUM_ALLOWED, RPC_UNICODE_STRING
from impacket.dcerpc.v5.lsat import DCERPCSessionError
from impacket.examples.utils import parse_target
from impacket.krb5.keytab import Keytab
from impacket.smbconnection import SMBConnection

SOCKET_TIMEOUT = 5


class LsaClient():
    def __init__(self, domain: str, username: str, password: str, host: str, kerberos: bool, kdc: str, lmhash: str, nthash: str) -> None:
        self.domain = domain
        self.username = username
        self.password = password
        self.host = host
        self.kerberos = kerberos
        self.lmhash = lmhash
        self.nthash = nthash
        self.kdc = kdc
        self.dce_client: DCERPC_v5 = None  # type: ignore

    def connect(self) -> None:
        rpc_transport: SMBTransport = DCERPCTransportFactory(f'ncacn_np:{self.host}[\\PIPE\\lsarpc]')  # type: ignore
        rpc_transport.set_connect_timeout(SOCKET_TIMEOUT)
        rpc_transport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)
        if self.kerberos:
            rpc_transport.set_kerberos(self.kerberos, kdcHost=self.kdc)
        rpc_transport.get_dce_rpc
        self.dce_client = rpc_transport.get_dce_rpc()
        self.dce_client.connect()
        self.dce_client.bind(lsat.MSRPC_UUID_LSAT)

    def open_policy(self) -> bytes:
        request = lsad.LsarOpenPolicy2()
        request['SystemName'] = NULL
        request['ObjectAttributes']['RootDirectory'] = NULL
        request['ObjectAttributes']['ObjectName'] = NULL
        request['ObjectAttributes']['SecurityDescriptor'] = NULL
        request['ObjectAttributes']['SecurityQualityOfService'] = NULL
        request['DesiredAccess'] = MAXIMUM_ALLOWED|lsat.POLICY_LOOKUP_NAMES
        resp = self.dce_client.request(request)
        return resp['PolicyHandle']

    def lookup_name(self, policy_handle: bytes, service: str) -> dict[str, Any]:
        request = lsat.LsarLookupNames()
        request['PolicyHandle'] = policy_handle
        request['Count'] = 1
        name1 = RPC_UNICODE_STRING()
        name1['Data'] = f'NT Service\\{service}'
        request['Names'].append(name1)
        request['TranslatedSids']['Sids'] = NULL
        request['LookupLevel'] = lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta
        resp = self.dce_client.request(request)
        return resp


def detect_services(opts: Namespace) -> None:
    lsa_client = LsaClient(opts.domain, opts.username, opts.password, opts.host, opts.k, opts.dc_ip, opts.lmhash, opts.nthash)
    lsa_client.connect()
    policy_handle = lsa_client.open_policy()

    for product in opts.configdata['products']:
        for service in product.get('services', ()):
            try:
                lsa_client.lookup_name(policy_handle, service['name'])
                print(json.dumps(dict(host=opts.host, product=product['name'], service=service['name'], description=service['description'])))
            except DCERPCSessionError as e:
                if e.error_code != 0xc0000073:  # STATUS_NONE_MAPPED
                    raise e


def detect_named_pipes(opts: Namespace) -> None:
    smb_client = SMBConnection(opts.host, opts.host)
    if opts.k:
        smb_client.kerberosLogin(opts.username, opts.password, opts.domain, opts.lmhash, opts.nthash, opts.aeskey, opts.dc_ip)
    else:
        smb_client.login(opts.username, opts.password, opts.domain, opts.lmhash, opts.nthash)

    for file in smb_client.listPath('IPC$', '\\*'):
        pipepath = file.get_longname()
        if opts.debug:
            print(json.dumps(dict(host=opts.host, pipe=pipepath)))
        for product in opts.configdata['products']:
            for pipe in product.get('pipes', ()):
                if PurePath(pipepath).match(pipe['name']):
                    print(json.dumps(dict(host=opts.host, product=product['name'], pipe=pipepath, processes=pipe['processes'])))


def main() -> None:
    parser = ArgumentParser(description='Detects named pipes and installed services without local admin privileges.')
    parser.add_argument('target', action='store', help='[[DOMAIN/]USERNAME[:PASSWORD]@]HOST')
    parser.add_argument('-debug', action='store_true', help='Enable debug output')
    parser.add_argument('-config', action='store', required=True, metavar='PATH', help='JSON config defining services and named pipes')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action='store', metavar='[LMHASH]:NTHASH', help='Pass the hash')
    group.add_argument('-k', action='store_true', help='Use Kerberos authentication, tries to grab credentials from $KRB5CCNAME')
    group.add_argument('-aeskey', action='store', metavar='HEXKEY', help='Pass the key')
    group.add_argument('-keytab', action='store', metavar='PATH', help='Read keys for SPN from keytab')
    group.add_argument('-no-pass', action='store_true', help='Do not ask for password')

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar='IPADDRESS', help='IP address of domain controller')
    group.add_argument('-target-ip', action='store', metavar='IPADDRESS', help='IP Address of target machine')

    opts = parser.parse_args()

    if opts.hashes is not None:
        opts.lmhash, opts.nthash = opts.hashes.split(':')
    else:
        opts.lmhash, opts.nthash = '', ''

    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG if opts.debug else logging.ERROR)
    opts.domain, opts.username, opts.password, opts.host = parse_target(opts.target)

    if not opts.target_ip:
        opts.target_ip = opts.host

    if not opts.domain:
        opts.domain = ''

    if opts.keytab:
        Keytab.loadKeysFromKeytab(opts.keytab, opts.username, opts.domain, opts)
        opts.k = True

    if not opts.password and opts.username and not opts.hashes and not opts.no_pass and not opts.aeskey:
        from getpass import getpass
        opts.password = getpass('password:')

    if opts.aeskey:
        opts.k = True

    with open(opts.config, 'r') as file:
        opts.configdata = json.load(file)

    try:
        detect_services(opts)
    except Exception as e:
        logging.exception(e)
    try:
        detect_named_pipes(opts)
    except Exception as e:
        logging.exception(e)


if __name__ == '__main__':
    main()
