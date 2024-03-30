import ipaddress
import subprocess
from pathlib import Path
import os

from .interface import WGInterface
from .config import WGConfig


class WGManager():
    def __init__(self,
                 default_network_prefix: int,
                 config_dir: Path = '/etc/wireguard',
                 default_name_prefix: str = 'wg',
                 default_pre_up_commands: list[str] = None,
                 default_post_up_commands: list[str] = None,
                 default_pre_down_commands: list[str] = None,
                 default_post_down_commands: list[str] = None,
                 default_dns: str = None,
                 default_mtu: int = None) -> None:
        if not os.path.isdir(config_dir):
            raise NotADirectoryError('Directory is not exists')
        self.config_dir = config_dir
        self.default_network_prefix = default_network_prefix
        self.default_name_prefix = default_name_prefix
        self.default_pre_up_commands = default_pre_up_commands
        self.default_post_up_commands = default_post_up_commands
        self.default_pre_down_commands = default_pre_down_commands
        self.default_post_down_commands = default_post_down_commands
        self.default_dns = default_dns
        self.default_mtu = default_mtu
        self.interfaces = []

    def _get_interfaces_names(self) -> list[str]:
        """
        Names of the interfaces in config directory.

        Returns:
            list[str]: Interfaces names.

        """
        interface_paths = Path(self.config_dir).glob('*.conf')
        return [interface_path.stem.split('.')[0] for interface_path in interface_paths]

    def _load_existing_interfaces(self):
        config_names = self._get_interfaces_names()
        interfaces = []
        if config_names:
            for config_name in config_names:
                config_path = os.path.join(self.config_dir, f'{config_name}.conf')
                interface = WGInterface(config=WGConfig.load(config_path))
                interfaces.append(interface)
        self.interfaces = interfaces

    def _generate_interface_name(self):
        names = self._get_interfaces_names()
        counter = 0
        while True:
            name = f'{self.default_name_prefix}{counter}'
            if name not in names:
                return name
            counter += 1

    def _get_free_subnetwork(self, network_prefix: int) -> ipaddress.IPv4Network:
        """
        Get free subnetwork with given prefix.
        Args:
            network_prefix(int): Subnetwork size need to be allocated.

        Returns:
            IPv4Network: Allocated free subnetwork.

        """
        local_network = ipaddress.ip_network('10.0.0.0/8')
        subnets = local_network.subnets(new_prefix=network_prefix)
        existing_subnets = [interface.config.interface_config.network for interface in self.interfaces]
        for subnet in subnets:
            if not any(subnet.overlaps(existing_subnet) for existing_subnet in existing_subnets):
                return subnet
        raise WGManager(f"No available subnet with prefix '{network_prefix}'")

    def _get_free_port(self,
                       range_start: int = 51820,
                       range_end: int = 65535) -> int:
        """
        Get free port in range allocated for interfaces.
        Args:
            range_start(int): Ports, allocated for interfaces, range start.
            range_end(int): Ports, allocated for interfaces, range end.

        Returns:
            int: First available port in range.

        """
        existing_ports = [interface.config.interface_config.listen_port for interface in self.interfaces]
        port_range = range(range_start, range_end)
        for port in port_range:
            if port not in existing_ports:
                return port

    def generate_new_interface(self,
                               name: str = None,
                               network_prefix: int = None,
                               dns: ipaddress.IPv4Address = None,
                               mtu: int = None,
                               table: int = None,
                               pre_up_commands: list[str] = None,
                               post_up_commands: list[str] = None,
                               pre_down_commands: list[str] = None,
                               post_down_commands: list[str] = None) -> WGInterface:

        if not name:
            name = self._generate_interface_name()
        if not network_prefix:
            network_prefix = self.default_network_prefix
        network = self._get_free_subnetwork(network_prefix)
        listen_port = self._get_free_port()
        if not dns:
            dns = self.default_dns
        if not mtu:
            mtu = self.default_mtu
        if not pre_up_commands:
            pre_up_commands = self.default_pre_up_commands
        if not post_up_commands:
            post_up_commands = self.default_post_up_commands
        if not pre_down_commands:
            pre_down_commands = self.default_pre_down_commands
        if not post_down_commands:
            post_down_commands = self.default_post_down_commands
        config_path = os.path.join(self.config_dir, f'{name}.conf')
        interface = WGInterface.create(config_path,
                                       network,
                                       listen_port)
        interface.config.interface_config.dns = dns
        interface.config.interface_config.mtu = mtu
        interface.config.interface_config.table = table
        interface.config.interface_config.pre_up = pre_up_commands
        interface.config.interface_config.post_up = post_up_commands
        interface.config.interface_config.pre_down = pre_down_commands
        interface.config.interface_config.post_down = post_down_commands
        interface.config.save()
        self._load_existing_interfaces()
        return interface
# TODO: TEST!
    def get_active_interfaces(self) -> tuple[WGInterface, ...]:
        active_interfaces_names = subprocess.run(['wg', 'show', 'interfaces'], capture_output=True).stdout.decode(
            'utf8').rstrip()
        active_interfaces_names = active_interfaces_names.split(' ')
        active_interfaces = []
        for interface in self.interfaces:
            if interface.config.name in active_interfaces_names:
                active_interfaces.append(interface)
        return tuple(active_interfaces)
# TODO: TEST
    def delete_interface(self, interface: WGInterface) -> None:
        """
        Gracefully remove interface.

        Raises:
            FileNotFoundError: if configuration file does not exist
        """
        interface.stop()
        interface.config.delete()
        self._load_existing_interfaces()

    def delete_all(self) -> None:
        for interface in self.interfaces:
            interface.delete()
