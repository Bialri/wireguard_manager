import ipaddress
import os.path
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
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
    with pytest.raises(InterfaceError):
        for i in range(257):
            interface.create_peer(str(i))

# TODO: finish test
def test_interface_generate_config(interface_config,peer_config):
    config = WGConfig(interface_config=interface_config,peer_configs=[peer_config])
    interface = WGInterface(config=config)
    interface.generate_peer_config(peer_config,'0.0.0.0')
    pass