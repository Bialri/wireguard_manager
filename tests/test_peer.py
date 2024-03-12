import codecs
import ipaddress

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from src.peer import WGPeer


def test_peer_create():
    peer = WGPeer(allowed_ips=ipaddress.IPv4Network('10.0.0.2/32'),
                  name='test')
    peer.set_key()
    assert peer.name == 'test'
    assert peer.allowed_ips == ipaddress.IPv4Network('10.0.0.2/32')


def test_peer_set_key():
    peer = WGPeer()
    peer.set_key()
    assert isinstance(peer.private_key, X25519PrivateKey)


def test_peer_from_config():
    private_key = X25519PrivateKey.generate()
    bytes_ = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_encoded = codecs.encode(bytes_, 'base64').decode('utf8').strip()
    public_key = private_key.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                                            format=serialization.PublicFormat.Raw)
    public_encoded = codecs.encode(public_key, 'base64').decode('utf8').strip()

    config = f"""[Peer]
# Name = test
AllowedIPs = 10.0.0.1/32
PublicKey = {public_encoded}
# PrivateKey = {private_encoded}"""
    peer = WGPeer.from_config(config)
    assert peer.name == 'test'
    assert peer.allowed_ips == ipaddress.IPv4Network("10.0.0.1/32")
    assert peer.private_key.public_key() == private_key.public_key()


def test_peer_interface_config():
    peer = WGPeer(allowed_ips=ipaddress.IPv4Network("10.0.0.1/32"),
                  name='test')
    peer.set_key()
    private_key = peer.private_key
    bytes_ = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_encoded = codecs.encode(bytes_, 'base64').decode('utf8').strip()

    config_expected = f"""[Interface]
Address = {str(peer.allowed_ips)}
PrivateKey = {private_encoded}
DNS = 1.1.1.1
"""
    config = peer.generate_interface_config()
    assert config_expected == config