# Taller_de_redes
Para empezar a relizar este trabajo se deben tomar los datos del anterior.
Por lo cual se deben de hacer todos los Dockers necesarios.
Entre estos se encuentra el del servidor el cual es de postgre y se abre con:

sudo docker pull postgres
docker run -e POSTGRES_PASSWORD=kali postgres

Una vez hecho esto se debe de crear el cliente con pgclip:

sudo docker build -t pgcli .
sudo docker run --name fin  -it pgcli pgcli  -h 172.17.0.2 -p 5432 -U postgres

Con esto se sabe que ip de servidor tenemos pero no de cliente por lo cual ahora se procede 
a buscar la ip del cliente con:

sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' fin


obtenemos ip servidor 172.17.0.2
obtenemos ip cliente 172.17.0.3

Ahora se hace el arp Spoof
con este vamos a corroborar que se esta leyendo el trafico.
Para esto oupamos el archivo arp_spoof.py 
El cual copiamos y pegamos en la terminal python.

Luego de esto debemos dar permisos para que la ip se pueda enviar y reenviar con esto:

echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

De aqui en adelante ocuparemos Scapy pero lo ocuparemos desde la consola con:

Sudo python3

Ahora se debe de copiar lo que esta dentro del 
Se llama sniffer_tare.py
Lo ejecutamos dentro de python y nos mostrara que los paquetes se guardaran.

De aqui se ejecuta la parte 2

ahora procedemos a lo segundo que es la modificacion de las consultas


Se sigue con este codigo que practicamente es la utilidad del psql
Es el que recibe la consulta en select y la pasa a delete.
psql_utils.py

Luego se ocupa el modify_pgsql.py
En este se envia la modificacion que se hizo con el utils y se pasa desde el clietne al servidor.
con esto ahora se recibe y pasa por todo el protocolo pgsql desde el cliente al servidor.

Una vez hecho esto se deberia ver en la terminal del sniffer como dice que se recibio un paquete.

Y en la terminal del modify se debe ver como se cambio desde un select a un modify

Con esos mensajes se da por cuncluido el trabajo.
