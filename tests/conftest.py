import pytest
import ipaddress
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from wireguard_manager.config import WGConfig, WGInterfaceConfig, WGPeerConfig


@pytest.fixture
def interface_config():
    return WGInterfaceConfig(ipaddress.ip_network("10.0.0.0/24"),
                             ipaddress.ip_address("10.0.0.1"),
                             59694,
                             X25519PrivateKey.generate(),
                             dns='test',
                             table=1,
                             mtu=1500,
                             pre_up='1',
                             post_up='2',
                             pre_down='3',
                             post_down='4')


@pytest.fixture
def interfaces_configs():
    config_1 = WGInterfaceConfig(ipaddress.ip_network("10.0.0.0/24"),
                             ipaddress.ip_address("10.0.0.1"),
                             59694,
                             X25519PrivateKey.generate(),
                             mtu=1500)

    config_2 = WGInterfaceConfig(ipaddress.ip_network("10.0.1.0/24"),
                                 ipaddress.ip_address("10.0.1.1"),
                                 59695,
                                 X25519PrivateKey.generate(),
                                 mtu=1500)

    config_3 = WGInterfaceConfig(ipaddress.ip_network("10.0.2.0/24"),
                                 ipaddress.ip_address("10.0.2.1"),
                                 59696,
                                 X25519PrivateKey.generate(),
                                 mtu=1500)
    return config_1, config_2, config_3


@pytest.fixture
def peer_config():
    return WGPeerConfig(ipaddress.ip_network('10.0.0.2/32'),
                        ipaddress.ip_address("10.0.0.2"),
                        'test',
                        X25519PrivateKey.generate(),
                        persistent_keep_alive=25,
                        endpoint='test')

@pytest.fixture
def peer_configs():
    configs = []
    for i in range(3):
        configs.append(WGPeerConfig(ipaddress.ip_network(f'10.0.0.{i+2}/32'),
                           ipaddress.ip_address(f"10.0.0.{i+2}"),
                           f'test{i}',
                           X25519PrivateKey.generate(),
                           persistent_keep_alive=25,
                           endpoint='test'))
    return configs
