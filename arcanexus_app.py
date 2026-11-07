import flet as ft
import requests

def main(page: ft.Page):
    page.title = "ArcaneXus OS - Edge Node 1121"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 30

    header = ft.Text("ARCANEXUS CONTROL PLANE", size=22, weight=ft.FontWeight.BOLD, color=ft.colors.CYAN_ACCENT)
    status_text = ft.Text("Substrate Status: AWAITING HANDSHAKE", color=ft.colors.RED_ACCENT)
    telemetry_display = ft.Text("No data.", font_family="monospace", size=14)
    
    def ping_substrate(e):
        try:
            response = requests.get("http://127.0.0.1:1121/api/status", timeout=3)
            data = response.json()
            shm = data.get("shm_state", {})
            status_text.value = f"Substrate Status: {data.get('status', 'ONLINE')}"
            status_text.color = ft.colors.GREEN_ACCENT
            telemetry_display.value = (
                f"Node ID: {shm.get('node_id', 'UNKNOWN')}\n"
                f"Gate: {shm.get('gate', 'LOCKED')}\n"
                f"Driver: {shm.get('f_driver', 0.0)} Hz\n"
                f"Ingress: {shm.get('f_ingress', 0.0)} Hz\n"
                f"Drift: {shm.get('delta_lambda', 0.0)}"
            )
        except Exception as ex:
            status_text.value = "OFFLINE"
            status_text.color = ft.colors.RED_ACCENT
            telemetry_display.value = f"Termux backend unreachable.\n{str(ex)}"
        page.update()

    ping_button = ft.ElevatedButton(text="PING EDGE SUBSTRATE", on_click=ping_substrate)

    page.add(header, status_text, telemetry_display, ping_button)

ft.app(target=main)
