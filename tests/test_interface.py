import ipaddress
import os.path
import subprocess

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
import codecs

from contextlib import nullcontext as does_not_raise
import pytest

from wireguard_manager.interface import WGInterface
from wireguard_manager.config import WGConfig
from wireguard_manager.exceptions import InterfaceError


def test_interface_create(tmp_path):
    config = os.path.join(tmp_path, 'wg0.conf')
    interface = WGInterface.create(config_path=config,
                                   network=ipaddress.ip_network('10.0.0.0/24'),
                                   listen_port=8000,
                                   address=ipaddress.ip_address('10.0.0.1'))
    assert interface.config.name == 'wg0'
    assert interface.config.path == config
    assert interface.config.interface_config.address == ipaddress.ip_address('10.0.0.1')
    assert interface.config.interface_config.network == ipaddress.ip_network('10.0.0.0/24')
    assert interface.config.interface_config.listen_port == 8000


def test_interface_create_without_options(tmp_path):
    config = os.path.join(tmp_path, 'wg0.conf')
    interface = WGInterface.create(config_path=config,
                                   network=ipaddress.ip_network('10.0.0.0/24'),
                                   listen_port=8000)
    assert interface.config.name == 'wg0'
    assert interface.config.path == config
    assert interface.config.interface_config.address == ipaddress.ip_address('10.0.0.1')
    assert interface.config.interface_config.network == ipaddress.ip_network('10.0.0.0/24')
    assert interface.config.interface_config.listen_port == 8000


@pytest.mark.parametrize('address,network,expected',
                         [
                             ('10.0.0.2', '10.0.0.2/32', does_not_raise()),
                             ('10.0.0.2', '10.0.0.3/32', pytest.raises(InterfaceError)),
                             ('10.1.0.2', '10.1.0.2/32', pytest.raises(InterfaceError)),
                         ])
def test_interface_create_peer(interface_config, address, network, expected):
    config = WGConfig(interface_config=interface_config)
    interface = WGInterface(config)
    private_key = X25519PrivateKey.generate()
    with expected:
        peer = interface.create_peer('test',
                                     ipaddress.ip_network(network),
                                     ipaddress.ip_address(address),
                                     private_key,
                                     25)
        assert len(interface.config.peer_configs) == 1
        assert peer.allowed_ips_address == ipaddress.ip_address(address)
        assert peer.allowed_ips_network == ipaddress.ip_network(network)
        assert peer.name == 'test'
        assert peer.private_key.public_key() == peer.private_key.public_key()
        assert peer.persistent_keep_alive == 25


def test_interface_create_peer_without_options(interface_config):
    config = WGConfig(interface_config=interface_config)
    interface = WGInterface(config)
    peer = interface.create_peer('test')
    assert peer.name == 'test'
    assert peer.allowed_ips_address == ipaddress.ip_address('10.0.0.2')
    assert peer.allowed_ips_network == ipaddress.ip_network('10.0.0.2/32')



def test_interface_create_peer_no_available_ips(interface_config):
    config = WGConfig(interface_config=interface_config)
    interface = WGInterface(config=config)
    for i in range(253):
        interface.create_peer(str(i))
    with pytest.raises(InterfaceError):
        interface.create_peer('throw exception')


def test_interface_generate_config(interface_config,peer_config):
    interface_key = interface_config.private_key.public_key()
    bytes_ = interface_key.public_bytes_raw()
    interface_key_line = codecs.encode(bytes_, 'base64').decode('utf8').strip()

    peer_key = peer_config.private_key
    bytes_ = peer_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    peer_key_line = codecs.encode(bytes_, 'base64').decode('utf8').strip()
    expected = f"""[Interface]
Address = 10.0.0.2/32
PrivateKey = {peer_key_line}
DNS = test
MTU = 1500


[Peer]
AllowedIPs = 0.0.0.0/0
PublicKey = {interface_key_line}
Endpoint = 0.0.0.0:{interface_config.listen_port}
"""
    config = WGConfig(interface_config=interface_config,peer_configs=[peer_config])
    interface = WGInterface(config=config)
    config = interface.generate_peer_config(peer_config,'0.0.0.0')
    assert config == expected


def test_interface_run(tmp_path,interfaces_configs):
    config_1 = WGConfig(os.path.join(tmp_path,'wg0.conf'),interfaces_configs[0])
    config_1.save()
    interface_1 = WGInterface(config_1)

    config_2 = WGConfig(os.path.join(tmp_path, 'wg1.conf'), interfaces_configs[1])
    config_2.save()
    interface_2 = WGInterface(config_2)

    config_3 = WGConfig(os.path.join(tmp_path, 'wg2.conf'), interfaces_configs[2])
    config_3.save()
    interface_3 = WGInterface(config_3)

    interface_1.run()
    interface_2.run()

    process = subprocess.run(['wg', 'show', 'interfaces'], capture_output=True)
    subprocess.run(['wg-quick', 'down', config_1.path])
    subprocess.run(['wg-quick', 'down', config_2.path])
    assert process.stdout.decode('utf-8').rstrip() == "wg0 wg1"


def test_interface_stop(tmp_path,interfaces_configs):
    config_1 = WGConfig(os.path.join(tmp_path, 'wg0.conf'), interfaces_configs[0])
    config_1.save()
    interface_1 = WGInterface(config_1)

    config_2 = WGConfig(os.path.join(tmp_path, 'wg1.conf'), interfaces_configs[1])
    config_2.save()
    interface_2 = WGInterface(config_2)

    config_3 = WGConfig(os.path.join(tmp_path, 'wg2.conf'), interfaces_configs[2])
    config_3.save()
    interface_3 = WGInterface(config_3)

    interface_1.run()
    interface_2.run()
    interface_3.run()

    interface_2.stop()

    process = subprocess.run(['wg', 'show', 'interfaces'], capture_output=True)
    assert process.stdout.decode('utf-8').rstrip() == "wg0 wg2"