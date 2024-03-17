import ipaddress
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
import codecs

from wireguard_manager.config import WGPeerConfig


def test_peer_config_read():
    config_text = """AllowedIPs = 10.0.0.3/32
PersistentKeepalive = 25
Endpoint = test
#Name = test
#PrivateKey = kLZt1UCoxgFR/F9EZThIrUNDo7PQ5Q2vNg/xCpMAEG8=
"""
    peer_config = WGPeerConfig.load(config_text)
    decoded_key = codecs.decode('kLZt1UCoxgFR/F9EZThIrUNDo7PQ5Q2vNg/xCpMAEG8='.encode('utf-8'), 'base64')
    private_key = X25519PrivateKey.from_private_bytes(decoded_key)
    assert peer_config.allowed_ips_network == ipaddress.ip_network('10.0.0.3/32')
    assert peer_config.allowed_ips_address == ipaddress.ip_address('10.0.0.3')
    assert peer_config.persistent_keep_alive == 25
    assert peer_config.endpoint == 'test'
    assert peer_config.name == 'test'
    assert peer_config.private_key.public_key() == private_key.public_key()


def test_peer_config_stringify():
    expected = """[Peer]
#Name = test
AllowedIPs = 10.0.0.3/32
PublicKey = U3aZHHO/zhIKZ6dNN+kK2Ym4feiwSxD9T9EkgXfLKhQ=
PersistentKeepalive = 25
Endpoint = test
#PrivateKey = kLZt1UCoxgFR/F9EZThIrUNDo7PQ5Q2vNg/xCpMAEG8=
"""
    decoded_private = codecs.decode('kLZt1UCoxgFR/F9EZThIrUNDo7PQ5Q2vNg/xCpMAEG8='.encode('utf-8'), 'base64')
    private_key = X25519PrivateKey.from_private_bytes(decoded_private)
    peer_config = WGPeerConfig(ipaddress.ip_network('10.0.0.3/32'),
                               ipaddress.ip_address("10.0.0.3"),
                               'test',
                               private_key,
                               25,
                               'test')
    assert peer_config.stringify() == expected

def test_peer_config_missing_optional_stringify():
    expected = """[Peer]
AllowedIPs = 10.0.0.3/32
PublicKey = U3aZHHO/zhIKZ6dNN+kK2Ym4feiwSxD9T9EkgXfLKhQ=
PersistentKeepalive = 25
#PrivateKey = kLZt1UCoxgFR/F9EZThIrUNDo7PQ5Q2vNg/xCpMAEG8=
"""
    decoded_private = codecs.decode('kLZt1UCoxgFR/F9EZThIrUNDo7PQ5Q2vNg/xCpMAEG8='.encode('utf-8'), 'base64')
    private_key = X25519PrivateKey.from_private_bytes(decoded_private)
    peer_config = WGPeerConfig(ipaddress.ip_network('10.0.0.3/32'),
                               ipaddress.ip_address("10.0.0.3"),
                               private_key=private_key,
                               persistent_keep_alive=25)
    assert peer_config.stringify() == expected
