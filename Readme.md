#### Instrukcje

Droplet IP: 139.59.156.11

Aby zainstalować snorta (powinno działać, ale nie wiem czy działa):  
```./active-firewall/install.sh```

#### Aby przetestować snorta  

HOST 1:
```
snort -d -l /var/log/snort/ -h 139.59.156.11/24 -A console -c /etc/snort/snort.conf
```

HOST 2:
```
sudo nmap -v -sT -O 139.59.156.11
```

#### Aby przetestować aplikacje
Uwaga:  
Narazie nie czyścimy komend, więc poniższy test spowoduje dodanie do iptables drop'a na source IP, lepiej nie podawać swojego bo jak jesteśmy na droplecie
czy innej maszynce remote to urwie nam połączenie i trzeba będzie zmienić IP, żeby przywrócić
```
touch plik
echo "Something" >> plik
tail -f plik | ./start.py
echo "ICMP PING NMAP [**] [Classification: Attempted Information Leak] [Priority: 2] {ICMP} 217.96.186.168 -> 139.59.156.11" >> plik
```

start.py potrzebuje roota więc albo zalogowani na roota, albo wykminić jak iptables wewnątrz pythona ma
robić sudo bez pytania o hasło. Lub testować na remote na maszynce jako root.

#### Rozwoj aplikacji

Wszystkie rule wrzucamy do pliku konfiguracyjnego local.rules. Podmieniamy domyslny plik snort.conf znajdujacym sie pod scieżką /etc/snort/snort.conf plikiem active_firewall/snort.conf (plik konfiguracyjny z zakomentowanymi domyslnymi regulami)

#### Syn Flood
Przypadek testowy:

HOST 2:

```
sudo apt install hping3

hping3 -V  -c 1000 -d 100 -S -p 21 --flood $ADRES_HOST_1
```

### Ping of Death

HOST2:

```
hping3 -i u10000 -1 -d 1200  46.101.122.137
```

### HTTP Flood

Reguła odpali się kiedy podczas 30 sekundowego okresu z jednego adresu IP zostanie wykonanych 30 żądań HTTP.

HOST1:

```
pip install simple_http_server

python -m SimpleHTTPServer 80
```

HOST2:

```
git clone https://github.com/TheFox/httpflood.git

sudo apt-get update && apt install cmake && sudo apt-get install build-essential

mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Release .. && make && make test

./bin/httpflood $HOST_1_IP 80

```

### Land attack

Land attack occurs when an attack host sends spoofed TCP SYN 
packets (connection initiation) with the target host's IP address 
and the TCP port as both source and destination. The reason a 
Land attack works is because it causes the machine to reply to 
itself continuously. That is, the target host responds by sending 
the SYN-ACK packet to itself, creating an empty connection that 
lasts until the idle timeout value is reached. Flooding a system 
with such empty connections can overwhelm the system, causing 
a DoS situation.

HOST1:

```
python -m SimpleHTTPServer 80
```

HOST2:
hping3 -V -c 1000 -d 100 -S -p 80 -s 80 -k -a 46.101.122.137 46.101.122.137
