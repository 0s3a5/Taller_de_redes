from scapy.all import *

interface = "docker0" 
postgres_server_ip = "172.17.0.2" 
postgres_client_ip = "172.17.0.3" 

filter_str = f"tcp port 5432 and (host 172.17.0.2 or host 172.17.0.3)"

print(f"Iniciando sniffing en la interfaz {interface} con filtro: {filter_str}")
print("¡Ahora, ve a tu terminal cliente (donde estás conectado a PostgreSQL) y realiza algunas operaciones SQL (SELECT, INSERT, etc.)!")

packets = sniff(filter=filter_str, count=1, iface=interface)

wrpcap("psql_traffic_captura.pcap", packets)

print("\nResumen de los paquetes capturados:")
packets.summary()
