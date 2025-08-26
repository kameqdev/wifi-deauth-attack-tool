from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Label
from textual.containers import Horizontal, VerticalScroll
from textual import log

from sniffer import NetworkScanner


def run_on_ui_thread(func):
    def wrapper(self, *args, **kwargs):
        self.call_from_thread(func, self, *args, **kwargs)
    return wrapper


class DeauthToolApp(App):
    BINDINGS = [('q', 'quit', 'Quit')]

    def __init__(self, interface='mon0'):
        super().__init__()
        self.scanner = NetworkScanner(
            interface=interface,
            on_ap_found=self._add_ap,
            on_client_found=self._add_client
        )

    # --- Textual App Methods ---
    def compose(self) -> ComposeResult:
        self.title = 'Wi-Fi Deauthentication Attack Tool'

        yield Header(show_clock=True, name=self.title, icon='🦊')

        with Horizontal():
            with VerticalScroll(id='ap_list'):
                yield Label('Access Points')
                self.ap_table = DataTable()
                self.ap_table.add_columns('BSSID', 'SSID')
                yield self.ap_table

            with VerticalScroll(id='client_list'):
                yield Label('Clients')
                self.clients_table = DataTable()
                self.clients_table.add_column('CLIENT', key='CLIENT')
                self.clients_table.add_column('AP_BSSID', key='AP_BSSID')
                self.clients_table.add_column('AP_SSID', key='AP_SSID')
                yield self.clients_table
                
        yield Footer()
                
    def on_mount(self):
        self.scanner.start()
    
    def on_unmount(self):
        self.scanner.stop()

    # --- Other methods ---
    @run_on_ui_thread
    def _add_ap(self, bssid, ssid):
        self.ap_table.add_row(bssid, ssid, key=bssid)
        for client in { k: v for k, v in self.scanner.known_clients.items() if v == bssid }:
            self.clients_table.update_cell(row_key=client, column_key='AP_SSID', value=ssid)

    @run_on_ui_thread
    def _add_client(self, client_mac, ap_bssid):
        if client_mac in self.clients_table.rows:
            self.clients_table.update_cell(row_key=client_mac, column_key='AP_BSSID', value=ap_bssid)
            self.clients_table.update_cell(row_key=client_mac, column_key='AP_SSID', value=self.scanner.known_aps.get(ap_bssid, ""))
        else:
            self.clients_table.add_row(client_mac, ap_bssid, self.scanner.known_aps.get(ap_bssid, ""), key=client_mac)


if __name__ == '__main__':
    app = DeauthToolApp()
    app.run()