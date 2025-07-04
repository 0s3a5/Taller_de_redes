# Taller_de_redes
Se crea un arp spoofing y modificacion de paquetes mediante Scapy

como hacer una cosa de redes que ni siquiera yo se como se hace pero se hace
intro
se debe hacer todo lo del anterioor para tener las conexiones
primero hacemos todo lo de la entrega anterior 
esto es conectar el servidor y el cliente
esto con 

sudo docker pull postgres
docker run -e POSTGRES_PASSWORD=kali postgres

y con
 sudo docker build -t pgcli .
sudo docker run --name fin  -it pgcli pgcli  -h 172.17.0.2 -p 5432 -U postgres

luego descubrimos cual es la ip del cliente con esto
lo que hace es ver la direccion del contenedor, le puse de nombre fin por que en realidad
se llamaba finales pero con cada prueba le iba quitando una letra XD

sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' fin   

obtenemos ip servidor 172.17.0.2
obtenemos ip cliente 172.17.0.3


ahora pasamos a la parte de desarrollo
aqui se explica que se debe primero esnifear (no se si exista esa palabra)
definicion de esnifear y procedes a explicar que una ip envia y la otra recibe


importante antes de inciar todo se debe de ocupar esta linea de codigo que permite que una ip se devuelva
con esto uno sabe que cosas se envian
y permite que el mensaje se cambie de select a delete

echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward



con esto creamos un archivo python el cual tuve que abrir desde la terminal porque no jalaba
este archivo lo voy a mandar igual y lo que hace es interceptar los mensajes mediante scapy
por eso se abre con python
en pocas palabras python=scapy

cambie esta basura y ya no se abre de terminal sino que se abre un .py
se llama snifer_tare.py
por alguna extrana razon sniffer me suena que significa jalar
pero del tipo jalar drogra

con esto listo pasamos al segundo punto 
si recien llevamos 1

parte 2 donde se indica que se tiene que entrar al envio de paquetes

ahora procedemos a lo segundo que es la modificacion de las consultas
hermano la mea vola se esta derritiendo la pantalla
quede loco


se sigue con este codigo que practicamente es la utilidad del psql
es el que recibe el largo de las consultas y toda la vola 
psql_utils.py se llama
aqui tinees que explicar que se tiene que abrir con sudo porque es literal una parte importante
que hace que se pueda modificar

despues se hace el modify.pqsql.py no se ni como se escribe revisa los nombres del github
en este se da la instruccion de que cada cosa que sea un select se cambia a un delete
otra vez hay que explicarlo con mas detalle no se escribir en linux asi que lo voy a subir a un github para que sea mas comodo ver todos los nombres y volas

parte 3 se hace corroboracion

al final se corrobora en el intercepcion al ver que se elimina la consulta en lugar de sleeccionar?
esto se hace con imagenes pero debes explicar que practicamente que se cumple porque en la imagen se ve y en el video tambien que se envia una solicitud selcet pero se modifica a un delete

conclusion

tengo sueno hambre escucho borrozo y no se que vola hice pero practicamente se que
se pueden modificar paquetes de postgre 
de que sirve
que en malas manos se puede ocupar para eliminar cosas importantes y que se puede ver la vulnerabilidad de ciertas cosas
de mas esta decir que no se como esto va a duncionar pero tengo fe de que esta lsito antes del viernes
jaja salu2
termine antes de la 1 pero veo borroso
la pantalla sigue derritiendose XD
