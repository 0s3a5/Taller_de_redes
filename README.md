Para empezar a realizar este trabajo se deben tomar los datos del anterior. Por lo cual se deben de hacer todos los Dockers necesarios. Entre estos se encuentra el del servidor el cual es de postgre y se abre con:

sudo docker pull postgres docker run -e POSTGRES_PASSWORD=kali postgres

Una vez hecho esto se debe de crear el cliente con pgclip:

sudo docker build -t pgcli . sudo docker run --name fin -it pgcli pgcli -h 172.17.0.2 -p 5432 -U postgres

Con esto se sabe que IP de servidor tenemos, pero no de cliente por lo cual ahora se procede a buscar la ip del cliente con:

sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' fin

obtenemos IP servidor 172.17.0.2 obtenemos IP cliente 172.17.0.3

Ahora se hace el arp Spoof con este vamos a corroborar que se está leyendo el tráfico. Para esto ocupamos el archivo arp_spoof.py El cual copiamos y pegamos en la terminal python.

Luego de esto debemos dar permisos para que la IP se pueda enviar y reenviar con esto:

echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

De aquí en adelante ocuparemos Scapy, pero lo ocuparemos desde la consola con:

Sudo python3

Ahora se debe de copiar lo que está dentro del Se llama sniffer_tare.py Lo ejecutamos dentro de python y nos mostrara que los paquetes se guardaran.

De aquí se ejecuta la parte 2

ahora procedemos a lo segundo que es la modificación de las consultas

Se sigue con este código que prácticamente es la utilidad del psql Es el que recibe la consulta en select y la pasa a delete. psql_utils.py

Luego se ocupa el modify_pgsql.py En este se envía la modificación que se hizo con el utils y se pasa desde el cliente al servidor. Con esto ahora se recibe y pasa por todo el protocolo pgsql desde el cliente al servidor.

Una vez hecho esto se debería ver en la terminal del sniffer como dice que se recibió un paquete.

Y en la terminal del modify se debe ver como se cambió desde un select a un modify

Con esos mensajes se da por concluido el trabajo.
