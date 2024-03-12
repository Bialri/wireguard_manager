import pytest
import os
import ipaddress

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
import codecs
from pathlib import Path

from src.interface import WGInterface


def test_interface_read_config_without_peers(tmp_path):
    config = """[Interface]
Address = 10.0.0.1/24
PostUp = iptables -I INPUT -p udp --dport 59694 -j ACCEPT
PostDown = iptables -D INPUT -p udp --dport 59694 -j ACCEPT
ListenPort = 59694
PrivateKey = kLZt1UCoxgFR/F9EZThIrUNDo7PQ5Q2vNg/xCpMAEG8="""
    test_interface_path = os.path.join(tmp_path, 'wg0.conf')
    decoded_key = codecs.decode("kLZt1UCoxgFR/F9EZThIrUNDo7PQ5Q2vNg/xCpMAEG8=".encode('utf-8'), 'base64')
    private_key = X25519PrivateKey.from_private_bytes(decoded_key)
    with open(test_interface_path, 'w') as file:
        file.write(config)

    interface = WGInterface.load_existing(test_interface_path)

    assert interface.peers == []
    assert interface.name == "wg0"
    assert Path(interface.config_dir) == Path(tmp_path)
    assert interface.network == ipaddress.ip_network("10.0.0.0/24")
    assert interface.address == ipaddress.ip_address("10.0.0.1")
    assert interface.listen_port == 59694
    assert interface.mtu is None
    assert interface.private_key.public_key() == private_key.public_key()
    assert interface.post_up_commands == ["iptables -I INPUT -p udp --dport 59694 -j ACCEPT"]
    assert interface.post_down_commands == ["iptables -D INPUT -p udp --dport 59694 -j ACCEPT"]


def test_interface_create_new(tmp_path):
    interface = WGInterface.create_new('wg',
                                       28,
                                       tmp_path)
    assert interface.name[:2] == 'wg'
    assert interface.network.prefixlen == 28


def test_interface_save(tmp_path):
    interface = WGInterface.create_new('wg',
                                       28,
                                       tmp_path)
    interface.save_config()

    config_path = os.path.join(tmp_path, f"{interface.name}.conf")
    assert os.path.exists(config_path)


def test_interface_run(tmp_path, capfd):
    interface = WGInterface.create_new('wg',
                                       28,
                                       tmp_path)
    interface.save_config()
    interface.run_interface()
    os.system('wg show interfaces')
    captured = capfd.readouterr()
    assert captured.out.rstrip() == interface.name


def test_interface_stop(tmp_path, capfd):
    interface = WGInterface.create_new('wg',
                                       28,
                                       tmp_path)
    interface.save_config()
    interface.run_interface()
    interface.stop_interface()
    os.system('wg show interfaces')
    captured = capfd.readouterr()
    assert captured.out.rstrip() == ''


def test_interface_delete(tmp_path, capfd):
    interface = WGInterface.create_new('wg',
                                       28,
                                       tmp_path)
    interface.save_config()
    interface.run_interface()
    interface.delete_config()
    os.system('wg show interfaces')
    captured = capfd.readouterr()
    assert captured.out.rstrip() == ''
    config_path = os.path.join(tmp_path, f'{interface.name}.conf')
    assert not os.path.exists(config_path)


def test_interface_get_command_line(tmp_path):
    test_lines = "Test = test\nNotTest = not_test"
    config_path = os.path.join(tmp_path, 'test')
    with open(config_path, 'w') as file:
        file.write(test_lines)
    matching = WGInterface._get_matching_config_line(config_path, 'Test')
    assert matching == 'test'


def test_interface_get_command_lines(tmp_path):
    test_lines = "Test = test\nNotTest = not_test\nTest = test2"
    config_path = os.path.join(tmp_path, 'test')
    with open(config_path, 'w') as file:
        file.write(test_lines)
    matching = WGInterface._get_matching_config_lines(config_path, 'Test')
    assert matching == ['test', 'test2']


def test_interface_config_peers(tmp_path):
    pass


def test_interface_free_ip(tmp_path):
    interface = WGInterface.create_new('wg',
                                       28,
                                       tmp_path)
    ip = interface._free_ip()
    assert ip == ipaddress.ip_address('10.0.0.2')


def test_interface_create_peer():
    pass


def test_interface_generate_config_line():
    line = WGInterface._generate_config_line('test','value')
    assert line == 'test = value\n'


def test_interface_generate_config_lines():
    lines = WGInterface._generate_config_lines('test', ['value','value2'])
    assert lines == 'test = value\ntest = value2\n'


def test_interface_generate_config(tmp_path):
    interface = WGInterface.create_new('wg',
                                       28,
                                       tmp_path)
    config = interface.generate_config()
    private_bytes = interface.private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_encoded = codecs.encode(private_bytes, 'base64').decode('utf8').strip()
    expected_config = f"""[Interface]
Address = 10.0.0.1/28
ListenPort = {interface.listen_port}
PrivateKey = {private_key_encoded}\n\n\n"""
    assert expected_config == config