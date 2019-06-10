# Aktywny Firewall
### Dokumentacja użytkownika
1. Pobrać lub sklonować źródła
2. ```cd /active-firewall```
3. ```./install.sh``` - skrypt instalacyjny przygotowuje program do działania, wymagany jest program snort, więc potrzebne zależności są doinstalowywane, podmieniana jest konfiguracja snort'a na przygotowaną przez nas w ramach projektu (własne reguły alertów dla konkretnych ataków)
4. ```./start.sh [host_ip]``` - skrypt do szybkiego uruchomienia programu, host_ip to ip naszego komputera

### Funkcjonalności
* Wykorzystanie programu Snort do analizy ruchu sieciowego i wykrywania ataków
* Stworzenie własnych reguł do wykrywania ataków (dodanie ich do konfiguracji programu Snort, w celu uzyskiwania alertów w momencie kiedy nastąpią):
  * Port Scanning
  * TCP DoS (SYN Flood)
  * Ping of Death
  * Land attack
  * GET Request Flood
  * UDP Flood
* Dynamiczne dodawanie nowych reguł firewall'a do systemu Linux
* Blokowanie atakującego: według IP i według Portów
  * Dla 1-3 alertu o ataku dla konkretnego portu, dodawane są reguły blokujące parę IP:Port
  * Dla 3+ regułach blokujących porty blokowane jest całe IP, w celu polepszenia bezpieczeństwa
* Usuwanie blokady po pewnym czasie, domyślnym (1 min) lub dłuższym / krótszym dla danego ataku

### Sposób działania
Dodane zostały nowe reguły ataków do programu snort:
```
alert tcp any any -> $HOME_NET any (flags: S; msg:"Possible TCP DoS"; flow: stateless; detection_filter: track by_dst, count 70, seconds 10; sid:10001;rev:1;)
alert icmp any any -> any any (msg:"Ping of Death Detected"; dsize:>1000; itype:8; icode:0; detection_filter:track by_src, count 30, seconds 1; sid:2000004; classtype:denial-of-service; rev:3;)
alert tcp any any -> any 80 (content:"HTTP"; msg:"GET Request flood attempt"; detection_filter:track by_src, count 5, seconds 30; metadata: service http; sid:2000006;)
alert tcp any any -> any any (msg: "Land attack detected"; flags:S; sameip; sid: 5000000; rev:1;)
alert udp any any -> $HOME_NET any (msg:"UDP flood attack detected"; flow: stateless; detection_filter: track by_dst, count 70, seconds 10 ; sid: 5000003; rev:1;)
```
Według tych reguł program snort będzie reagował na ruch sieci i logował wiadomości, że w systemie nastąpił atak (nazwy ataków w polu msg). Sam snort służy do monitoringu, jest to program typu IDS (Intrusion Detection System), wykrywa ataki sieciowe, aczkolwiek sam w sobie nie jest aktywnym firewallem. Ze snort'a otrzymujemy alerty, które następnie parsuje nasz program - skrypt w języku Python. Odbiera ze snorta informacje o adresie i portach podejmujących atak, a także o typie ataku i na podstawie tych informacji dodaje wpisy do iptables.

W osobnym wątku działa czyszczenie reguł, lądują one w kolejce, aby uniknąć problemów z wielowątkową manipulacją kolekcjami. Wątek czyszczący (cleaner) sprawdza czy minął ich "termin ważnośći" (każdej regule którą dodajemy ustawiamy odpowiedni czas obowiązywania, aby nie doprowadzić do sytuacji ogromnej ilośći reguł), jeśli tak to są usuwane z iptables,  w odwrotnym przypadku znowu lądują w kolejce do następnego sprawdzenia po pewnym czasie.

### Testowanie funkcjonalności
Aby przetestować aplikacje należy dokonać jednego z ataków przedstawionych poniżej w kierunku hosta. Spowoduje to dodanie blokujących reguł do iptables, domyślnie pozostaną one blokowane przez około minutę. Jeśli atak nadal będzie trwał, atakujący zostanie ponownie zablokowany.

#### Port Scanning
HOST 1:
```
./start.sh [host_ip]
```

HOST 2:
```
sudo nmap -v -sT -O [host_ip]
```

Aktywny firewall potrzebuje uprawnień administratora więc polecamy testowanie na zdalnej maszynie jako administrator.

#### Syn Flood
HOST 1:
```
./start.sh [host_ip]
```

HOST 2:
```
sudo apt install hping3
hping3 -V  -c 1000 -d 100 -S -p 21 --flood $ADRES_HOST_1
```

#### Ping of Death
HOST 1:
```
./start.sh [host_ip]
```

HOST 2:
```
sudo apt install hping3
hping3 -i u10000 -1 -d 1200  46.101.122.137
```

#### HTTP Flood
Reguła odpali się kiedy podczas 30 sekundowego okresu z jednego adresu IP zostanie wykonanych 30 żądań HTTP.

HOST 1:
```
pip install simple_http_server
python -m SimpleHTTPServer 80 &
./start.sh [host_ip]
```

HOST 2:
```
git clone https://github.com/TheFox/httpflood.git
sudo apt-get update && apt install cmake && sudo apt-get install build-essential
mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Release .. && make && make test
./bin/httpflood $HOST_1_IP 80
```

#### Land attack
Land attack występuje, gdy host atakujący wysyła sfałszowane pakiety TCP SYN z adresem hosta docelowego jako źródłem i miejscem docelowym. Przyczyną działania land attack jest to, że powoduje, że maszyna wciąż odpowiada do siebie. Oznacza to, że host docelowy odpowiada wysyłając do siebie pakiet SYN-ACK, tworząc puste połączenie, które trwa do momentu osiągnięcia limitu czasu bezczynności. Zalanie systemu takimi pustymi połączeniami może zablokować system, powodując atak DoS.

HOST 1:
```
pip install simple_http_server
python -m SimpleHTTPServer 80 &
./start.sh [host_ip]
```

HOST 2:
```
hping3 -V -c 1000 -d 100 -S -p 80 -s 80 -k -a 46.101.122.137 46.101.122.137
```

#### UDP Flood
UDP Flood polega na zalaniu docelowych portów UDP na systemie docelowym pakietami UDP (wywołując blokowanie lub spowolnienie systemu - DoS).

W pakiecie UDP należy ustawić źródłowy adres IP do sfałszowanego lub losowego adresu IP. Docelowy port UDP należy ustawić na liczbę otwartego portu UDP na hoście ofiary (wykrytego na przykład z pomocą skanowania portów).

HOST 1:
```
./start.sh [host_ip]
```

HOST 2:
```
hping3 -2 -V -c 1000 -d 100 -S -p 21 --flood 46.101.122.137
```
