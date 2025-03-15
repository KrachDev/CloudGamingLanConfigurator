import sys
import subprocess
import re
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QInputDialog, QMessageBox

class NetworkConfigApp(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Sunshine & Moonlight Ethernet Config")
        self.setGeometry(100, 100, 400, 300)

        layout = QVBoxLayout()

        self.label = QLabel("Choose your role:")
        layout.addWidget(self.label)

        self.host_button = QPushButton("Host (Sunshine)")
        self.host_button.clicked.connect(self.configure_host)
        layout.addWidget(self.host_button)

        self.client_button = QPushButton("Client (Moonlight)")
        self.client_button.clicked.connect(self.configure_client)
        layout.addWidget(self.client_button)

        self.restore_button = QPushButton("Restore Default (DHCP)")
        self.restore_button.clicked.connect(self.restore_default)
        layout.addWidget(self.restore_button)

        self.status_label = QLabel("")
        layout.addWidget(self.status_label)

        self.setLayout(layout)

        self.check_ethernet_connection()
        self.update_network_info()

    def run_command(self, command):
        """ Run a system command silently and return output """
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            self.status_label.setText(f"Error: {e}")
            return ""

    def get_active_ethernet(self):
        """ Get the active Ethernet interface name, filter out Wi-Fi interfaces """
        output = self.run_command('netsh interface show interface')
        
        # Debug log: print the raw output to console
        print("Debug Output (get_active_ethernet):\n", output)

        match = re.search(r"^\s*Enabled\s+Connected\s+Dedicated\s+(\S+)$", output, re.MULTILINE)
        return match.group(1) if match else None

    def check_ethernet_connection(self):
        """ Check if there is an active Ethernet connection, show dialog if not """
        eth_name = self.get_active_ethernet()

        if eth_name is None:
            self.status_label.setText("No active Ethernet connection found.")
            self.show_connection_dialog()
        else:
            self.status_label.setText(f"Active Ethernet: {eth_name}")

    def configure_host(self):
        """ Set up Ethernet for Sunshine (Host) """
        self.status_label.setText("Configuring Host (Sunshine)...")
        eth_name = self.get_active_ethernet()

        if eth_name:
            # Set static IP for host (Only IPv4)
            print(f"Setting Host (Sunshine) Static IP: 192.168.1.1 and Subnet: 255.255.255.0")
            ip_command = f'netsh interface ip set address name="{eth_name}" static 192.168.1.1 255.255.255.0'
            gateway_command = f'netsh interface ip set address name="{eth_name}" gateway=192.168.1.254'
            
            self.run_command(ip_command)
            self.run_command(gateway_command)
            self.run_command(f'netsh interface ip set address name="{eth_name}" static 192.168.1.1 255.255.255.0')

            self.status_label.setText("Host configured! Start Sunshine.")
            self.update_network_info()
        else:
            self.status_label.setText("No active Ethernet connection found.")

    def configure_client(self):
        """ Set up Ethernet for Moonlight (Client) """
        self.status_label.setText("Configuring Client (Moonlight)...")
        eth_name = self.get_active_ethernet()

        if eth_name:
            # Set static IP for client (Only IPv4)
            print(f"Setting Client (Moonlight) Static IP: 192.168.1.2 and Subnet: 255.255.255.0")
            ip_command = f'netsh interface ip set address name="{eth_name}" static 192.168.1.2 255.255.255.0'
            gateway_command = f'netsh interface ip set address name="{eth_name}" gateway=192.168.1.254'
            
            self.run_command(ip_command)
            self.run_command(gateway_command)
            self.run_command(f'netsh interface ip set address name="{eth_name}" static 192.168.1.2 255.255.255.0 192.168.1.1')

            self.status_label.setText("Client configured! Start Moonlight and connect to 192.168.1.1.")
            self.update_network_info()
        else:
            self.status_label.setText("No active Ethernet connection found.")

    def restore_default(self):
        """ Restore IPv4 settings to DHCP """
        self.status_label.setText("Restoring default settings...")
        eth_name = self.get_active_ethernet()

        if eth_name:
            # Restore DHCP for the interface
            self.run_command(f'netsh interface ip set address name="{eth_name}" dhcp')

            # Restore default gateway to DHCP
            self.run_command(f'netsh interface ip set address name="{eth_name}" gateway dhcp')

            # Reset other settings if needed (DNS, etc.)
            self.run_command(f'netsh interface ip set dns name="{eth_name}" dhcp')

            self.status_label.setText("IPv4 settings restored to DHCP.")
            self.update_network_info()  # To show the network details (now null or DHCP)
        else:
            self.status_label.setText("No active Ethernet connection found.")

    def update_network_info(self):
        """ Fetch and display current IPv4 network configuration in labels, restricted to Ethernet """
        eth_name = self.get_active_ethernet()
        if eth_name:
            output = self.run_command('ipconfig')
            
            # Extract IPv4 Address, Subnet Mask, and Gateway for Ethernet only
            ip = self.extract_info(output, "IPv4 Address", eth_name)
            subnet = self.extract_info(output, "Subnet Mask", eth_name)
            gateway = self.extract_info(output, "Default Gateway", eth_name)

        else:
            self.ip_label.setText("Current IP: N/A")
            self.subnet_label.setText("Subnet Mask: N/A")
            self.gateway_label.setText("Default Gateway: N/A")

    def extract_info(self, output, label, interface):
        """ Extract network info (IP, Subnet, Gateway) from ipconfig output """
        match = re.search(rf"({interface}[^:]*:\s*\w+[\w\s]+:{label}[^:]*: ([^\r\n]+))", output)
        return match.group(2) if match else "N/A"

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkConfigApp()
    window.show()
    sys.exit(app.exec())
