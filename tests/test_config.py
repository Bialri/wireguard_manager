import pytest
from contextlib import nullcontext as does_not_raise
import os

from wireguard_manager.config import WGConfig, WGInterfaceConfig
from wireguard_manager.exceptions import ConfigSyntaxError


@pytest.mark.parametrize('config_text,expectation',
                         [
                             ('[Interface]\nAddress = 10.0.0.1/24\nPostUp = test\nPostDown = test\nListenPort'
                              ' = 59694\nPrivateKey = kLZt1UCoxgFR/F9EZThIrUNDo7PQ5Q2vNg/xCpMAEG8=', does_not_raise()),
                             ('[Interface]\nWrong = test\nAddress = 10.0.0.1/24\nPostUp = test\nPostDown = test'
                              '\nListenPort = 59694\nPrivateKey = kLZt1UCoxgFR/F9EZThIrUNDo7PQ5Q2vNg/xCpMAEG8=',
                              pytest.raises(ConfigSyntaxError))
                         ])
def test_config_read_config_without_peers(tmp_path, config_text, expectation):
    test_interface_path = os.path.join(tmp_path, 'wg0.conf')
    with open(test_interface_path, 'w') as file:
        file.write(config_text)

    interface_config = WGInterfaceConfig.load(config_text)
    with expectation:
        interface = WGConfig.load(test_interface_path)
        assert interface.interface_config == interface_config


def test_config_read_not_existing():
    with pytest.raises(FileNotFoundError):
        WGConfig.load('/test')


def test_config_stringfy_without_peers(interface_config):
    expected = f"""{interface_config.stringify()}\n\n"""
    config_path = '/test'
    config = WGConfig(path=config_path, interface_config=interface_config)

    stringified = config.stringify()
    assert stringified == expected


def test_config_stringify_with_peers(interface_config, peer_configs):
    expected = f"{interface_config.stringify()}\n\n{peer_configs[0].stringify()}\n{peer_configs[1].stringify()}\n{peer_configs[2].stringify()}"

    config_path = '/test'
    config = WGConfig(path=config_path, interface_config=interface_config, peer_configs=peer_configs)
    assert config.stringify() == expected


def test_config_save(tmp_path, interface_config):
    path = os.path.join(tmp_path, 'test.conf')
    config = WGConfig(path=path, interface_config=interface_config)
    config.save()
    assert os.path.exists(path)


def test_config_delete(tmp_path, interface_config):
    path = os.path.join(tmp_path, 'test.conf')
    config = WGConfig(path=path, interface_config=interface_config)
    config.save()
    config.delete()
    assert not os.path.exists(path)
