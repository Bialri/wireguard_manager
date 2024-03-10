import ipaddress
import subprocess

from .utils import WGUtilsMixin
from pathlib import Path
import os

from .interface import WGInterface


class WGManager(WGUtilsMixin):
    def __init__(self,
                 config_dir: Path,
                 config_prefix: str,
                 default_network_prefix: int,
                 postup_command_templates: list[str],
                 postdown_command_templates: list[str],
                 default_dns: ipaddress.IPv4Address = ipaddress.IPv4Address('1.1.1.1'),
                 default_mtu: int = None) -> None:
        if not config_dir.is_dir():
            raise FileExistsError('directory is not exists')
        self.config_dir = config_dir
        self.config_prefix = config_prefix
        self.default_network_prefix = default_network_prefix
        self._load_existing_interfaces()
        self.postup_command_templates = postup_command_templates
        self.postdown_command_templates = postdown_command_templates
        self.default_dns = default_dns
        self.default_mtu = default_mtu

    def _load_existing_interfaces(self) -> tuple[WGInterface, ...]:
        config_names = self._get_interfaces_names(self.config_dir)
        interfaces = []
        for config_name in config_names:
            config_path = os.path.join(self.config_dir, f'{config_name}.conf')
            interface = WGInterface.load_existing(config_path)
            interfaces.append(interface)
        self.interfaces = interfaces

    def create_new_interface(self,
                             network_prefix: int = None,
                             dns: ipaddress.IPv4Address = None,
                             mtu: int = None) -> WGInterface:
        if not dns:
            dns = self.default_dns
        if not mtu:
            mtu = self.default_mtu
        if not network_prefix:
            network_prefix = self.default_network_prefix
        interface = WGInterface.create_new(self.config_prefix,
                                           network_prefix,
                                           self.config_dir,
                                           mtu,
                                           self.postup_command_templates,
                                           self.postdown_command_templates)
        interface.save_config()
        interface.run_interface()
        self._load_existing_interfaces()
        return interface

    def get_active_interfaces(self) -> tuple[WGInterface, ...]:
        active_interfaces_names = subprocess.run(['wg', 'show', 'interfaces'], capture_output=True).stdout.decode(
            'utf8').rstrip()
        active_interfaces_names = active_interfaces_names.split(' ')
        active_interfaces = []
        for interface in self.interfaces:
            if interface.name in active_interfaces_names:
                active_interfaces.append(interface)
        return tuple(active_interfaces)

    def delete_interface(self, interface: WGInterface) -> None:
        interface.stop_interface()
        interface.delete_config()
        self._load_existing_interfaces()

    def delete_all(self) -> None:
        for interface in self.interfaces:
            self.delete_interface(interface)