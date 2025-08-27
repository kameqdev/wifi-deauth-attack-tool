from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Label, Input, Rule
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.validation import Integer, Number
import threading

from sniffer import NetworkScanner
from attack import perform_deauth


def run_in_ui_thread(func):
    def wrapper(self, *args, **kwargs):
        self.call_from_thread(func, self, *args, **kwargs)
    return wrapper


class DeauthToolApp(App):
    CSS = """#config_container { height: 2; }"""
    
    BINDINGS = [('q', 'quit', 'Quit'),
                ('d', 'deauth', 'Deauth target'),
                ('r', 'rescan', 'Rescan for networks')]

    def __init__(self, interface='mon0'):
        super().__init__()
        self.interface = interface
        self.scanner = NetworkScanner(
            interface=interface,
            on_ap_found=self._add_ap,
            on_client_found=self._add_client
        )

    # --- Textual App Methods ---
    def compose(self) -> ComposeResult:
        self.title = 'Wi-Fi Deauthentication Attack Tool'

        yield Header(show_clock=True, name=self.title, icon='🦊')

        yield from self.data_tables_section()
        yield Rule()
        yield from self.config_section()

        yield Footer()

    def data_tables_section(self) -> ComposeResult:
        with Horizontal(id='tables_container'):
            with VerticalScroll(id='ap_list'):
                yield Label('Access Points')
                self.ap_table = DataTable(zebra_stripes=True, cursor_type='row')
                self.ap_table.add_columns('BSSID', 'SSID')
                yield self.ap_table

            with VerticalScroll(id='client_list'):
                yield Label('Clients')
                self.clients_table = DataTable(zebra_stripes=True, cursor_type='row')
                self.clients_table.add_column('CLIENT', key='CLIENT')
                self.clients_table.add_column('AP_BSSID', key='AP_BSSID')
                self.clients_table.add_column('AP_SSID', key='AP_SSID')
                yield self.clients_table
                
    def config_section(self) -> ComposeResult:
        with Vertical(id="config_container"):
            with Horizontal():
                yield Label("Packet Count: ")
                yield Input(value="100", id="count_input", validators=[Integer(minimum=1)], compact=True)
            with Horizontal():
                yield Label("Interval (s): ")
                yield Input(value="0.1", id="interval_input", type='number', validators=[Number(minimum=0)], compact=True)

    def on_mount(self):
        self.scanner.start()
    
    def on_unmount(self):
        self.scanner.stop()
        
    # --- Bindings ---
    def action_deauth(self):
        target = None
        bssid = None
        if self.ap_table.has_focus:
            target = self.ap_table.get_row_at(self.ap_table.cursor_row)[0]
        elif self.clients_table.has_focus:
            target, bssid, *_ = self.clients_table.get_row_at(self.clients_table.cursor_row)
        else:
            self.notify("No target selected for deauth.", severity="error", timeout=2)
            return
        
        count_input = self.query_one("#count_input")
        interval_input = self.query_one("#interval_input")
        if not count_input.is_valid or not interval_input.is_valid:
            self.notify("Invalid count or interval.", severity="error", timeout=2)
            return
        count = int(count_input.value)
        interval = float(interval_input.value)

        self.notify(f"Sending deauth to {target}{f' via {bssid}' if bssid else ''} on {self.interface}", timeout=2)
        def callback():
            self.call_from_thread(self.notify, f"Deauth attack on {target} completed.", timeout=2)
        threading.Thread(target=perform_deauth, args=(self.interface, target, bssid, count, interval, callback)).start()

    def action_rescan(self):
        self.scanner.stop()
        self.ap_table.clear()
        self.clients_table.clear()
        self.scanner = NetworkScanner(
            interface=self.interface,
            on_ap_found=self._add_ap,
            on_client_found=self._add_client
        )
        self.scanner.start()

    # --- Other methods ---
    @run_in_ui_thread
    def _add_ap(self, bssid, ssid):
        self.ap_table.add_row(bssid, ssid, key=bssid)
        for client in { k: v for k, v in self.scanner.known_clients.items() if v == bssid }:
            self.clients_table.update_cell(row_key=client, column_key='AP_SSID', value=ssid)

    @run_in_ui_thread
    def _add_client(self, client_mac, ap_bssid):
        if client_mac in self.clients_table.rows:
            self.clients_table.update_cell(row_key=client_mac, column_key='AP_BSSID', value=ap_bssid)
            self.clients_table.update_cell(row_key=client_mac, column_key='AP_SSID', value=self.scanner.known_aps.get(ap_bssid, ""))
        else:
            self.clients_table.add_row(client_mac, ap_bssid, self.scanner.known_aps.get(ap_bssid, ""), key=client_mac)


if __name__ == '__main__':
    app = DeauthToolApp()
    app.run()