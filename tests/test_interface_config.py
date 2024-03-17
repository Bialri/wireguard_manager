import ipaddress
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
import codecs

from wireguard_manager.config import WGInterfaceConfig


def test_interface_config_read():
    config_text = """Address = 10.0.0.1/24
ListenPort = 59694
PrivateKey = kLZt1UCoxgFR/F9EZThIrUNDo7PQ5Q2vNg/xCpMAEG8=
DNS = test
Table = 1
MTU = 1500
PreUp = 1
PostUp = 2
PreDown = 3
PostDown = 4
"""
    interface_config = WGInterfaceConfig.load(config_text)
    decoded_key = codecs.decode('kLZt1UCoxgFR/F9EZThIrUNDo7PQ5Q2vNg/xCpMAEG8='.encode('utf-8'), 'base64')
    private_key = X25519PrivateKey.from_private_bytes(decoded_key)
    assert interface_config.network == ipaddress.ip_network('10.0.0.0/24')
    assert interface_config.address == ipaddress.ip_address('10.0.0.1')
    assert interface_config.listen_port == 59694
    assert interface_config.private_key.public_key() == private_key.public_key()
    assert interface_config.dns == 'test'
    assert interface_config.table == 1
    assert interface_config.mtu == 1500
    assert interface_config.pre_up == ['1']
    assert interface_config.post_up == ['2']
    assert interface_config.pre_down == ['3']
    assert interface_config.post_down == ['4']


def test_interface_config_stringify():
    expected = """[Interface]
Address = 10.0.0.1/24
ListenPort = 59694
PrivateKey = kLZt1UCoxgFR/F9EZThIrUNDo7PQ5Q2vNg/xCpMAEG8=
DNS = test
Table = 1
MTU = 1500
PreUp = 1
PostUp = 2
PreDown = 3
PostDown = 4
"""
    decoded_key = codecs.decode('kLZt1UCoxgFR/F9EZThIrUNDo7PQ5Q2vNg/xCpMAEG8='.encode('utf-8'), 'base64')
    private_key = X25519PrivateKey.from_private_bytes(decoded_key)
    interface_config = WGInterfaceConfig(ipaddress.ip_network("10.0.0.0/24"),
                                         ipaddress.ip_address("10.0.0.1"),
                                         59694,
                                         private_key,
                                         'test',
                                         1,
                                         1500,
                                         ['1'],
                                         ['2'],
                                         ['3'],
                                         ['4'])
    assert interface_config.stringify() == expected


def test_interface_config_missing_optional_stringify():
    expected = """[Interface]
Address = 10.0.0.1/24
ListenPort = 59694
PrivateKey = kLZt1UCoxgFR/F9EZThIrUNDo7PQ5Q2vNg/xCpMAEG8=
Table = 1
MTU = 1500
PreUp = 1
PostDown = 4
"""
    decoded_key = codecs.decode('kLZt1UCoxgFR/F9EZThIrUNDo7PQ5Q2vNg/xCpMAEG8='.encode('utf-8'), 'base64')
    private_key = X25519PrivateKey.from_private_bytes(decoded_key)
    interface_config = WGInterfaceConfig(ipaddress.ip_network("10.0.0.0/24"),
                                         ipaddress.ip_address("10.0.0.1"),
                                         59694,
                                         private_key,
                                         table=1,
                                         mtu=1500,
                                         pre_up=['1'],
                                         post_down=['4'])
    print(interface_config.stringify())
    assert interface_config.stringify() == expected