#!/bin/bash

# pozwalamy na dostęp przez SSH z sieci wewnętrznej (dla celów administracyjnych)
iptables -A INPUT -s 184.254.213.0/24 -p tcp --dport 22 -j ACCEPT

# możemy też umożliwić dostęp tylko z konkretnego adresu administracyjnego
iptables -A INPUT -s 185.254.214.200 -p tcp --dport 22 -j ACCEPT

# ewentualnie (gdybyśmy nie chcieli wprowadzać powyżej whitelisty, tylko umożliwić połączenia z dowolnego adresu) możemy wprowadzić limit połączeń także dla SSH (w konfiguracji anty DDoS wprowadziliśmy limit połączeń dla HTTP i HTTPS, w związku z tym nasze aplikacje są odpowiednio chronione, ponadto stosujemy w nich “wolny” algorytmy kryptograficzny bcrypt, który skutecznie spowalnia łamanie haseł metodą brute force, jednak jeśli chcemy dodatkowym zabezpieczeniem objąć również SSH, należy wprowadzić connection limit jak niżej)
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP
