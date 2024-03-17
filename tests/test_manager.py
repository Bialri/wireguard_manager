import ipaddress
from pathlib import Path
from wireguard_manager.manager import WGManager


def test_manager_generate_interface(tmp_path):
    manager = WGManager(28,
                        config_dir=tmp_path,
                        default_pre_up_commands=['1'],
                        default_post_up_commands=['2'],
                        default_pre_down_commands=['3'],
                        default_post_down_commands=['4'],
                        default_dns='test',
                        default_mtu=1500)
    interface = manager.generate_new_interface()
    assert interface.config.interface_config.network.prefixlen == 28
    assert interface.config.name == 'wg0'
    assert interface.config.interface_config.dns == 'test'
    assert interface.config.interface_config.mtu == 1500
    assert interface.config.interface_config.pre_up == ['1']
    assert interface.config.interface_config.post_up == ['2']
    assert interface.config.interface_config.pre_down == ['3']
    assert interface.config.interface_config.post_down == ['4']


def test_manager_generate_interface_between(tmp_path):
    manager = WGManager(28,
                        config_dir=tmp_path,
                        default_pre_up_commands=['1'],
                        default_post_up_commands=['2'],
                        default_pre_down_commands=['3'],
                        default_post_down_commands=['4'],
                        default_dns='test',
                        default_mtu=1500)
    interface = manager.generate_new_interface()
    interface2 = manager.generate_new_interface(network_prefix=24)
    interface3 = manager.generate_new_interface()
    assert interface.config.interface_config.network == ipaddress.ip_network('10.0.0.0/28')
    assert interface2.config.interface_config.network == ipaddress.ip_network('10.0.1.0/24')
    assert interface3.config.interface_config.network == ipaddress.ip_network('10.0.0.16/28')
    assert interface.config.interface_config.address == ipaddress.ip_address('10.0.0.1')
    assert interface2.config.interface_config.address == ipaddress.ip_address('10.0.1.1')
    assert interface3.config.interface_config.address == ipaddress.ip_address('10.0.0.17')
    assert interface.config.name == 'wg0'
    assert interface2.config.name == 'wg1'
    assert interface3.config.name == 'wg2'