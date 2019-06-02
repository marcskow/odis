#!/bin/bash

# usuwamy komendę, która ma dropować wszystkie zapytania, których nie obsłużyliśmy do tej pory, ponieważ chcemy dokleić nowe
# reguły, jeśli odpalamy ten skrypt jako jedyny, nie musielibyśmy tego robić, możemy otrzymać komunikat że nie ma reguły
# którą usuwamy, aczkolwiek w razie gdyby istniała już inna konfiguracja, przygotowujemy się na taką ewentualność
iptables -D INPUT -p tcp -m state --state NEW -j DROP

# pozwalamy na dostęp przez SSH z sieci wewnętrznej (dla celów administracyjnych)
iptables -A INPUT -s 184.254.213.0/24 -p tcp --dport 22 -j ACCEPT

# możemy też umożliwić dostęp tylko z konkretnego adresu administracyjnego
iptables -A INPUT -s 185.254.214.200 -p tcp --dport 22 -j ACCEPT

# ewentualnie (gdybyśmy nie chcieli wprowadzać powyżej whitelisty, tylko umożliwić połączenia z dowolnego adresu) możemy wprowadzić limit połączeń także dla SSH (w konfiguracji anty DDoS wprowadziliśmy limit połączeń dla HTTP i HTTPS, w związku z tym nasze aplikacje są odpowiednio chronione, ponadto stosujemy w nich “wolny” algorytmy kryptograficzny bcrypt, który skutecznie spowalnia łamanie haseł metodą brute force, jednak jeśli chcemy dodatkowym zabezpieczeniem objąć również SSH, należy wprowadzić connection limit jak niżej)
iptables -A INPUT -p tcp -m tcp --dport 22 -m state --state NEW -m recent --set --name DEFAULT --rsource
iptables -A INPUT -p tcp -m tcp --dport 22 -m state --state NEW -m recent --update --seconds 180 --hitcount 4 --name DEFAULT --rsource -j DROP
iptables -A INPUT -p tcp -m state --state NEW --dport 22 -j ACCEPT

# drop any other requests
iptables -A INPUT -p tcp -m state --state NEW -j DROP
