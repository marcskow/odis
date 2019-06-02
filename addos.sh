#!/bin/bash

# czyszczenie dotychczasowej konfiguracji
iptables --flush

# zabezpieczenie przed SYN Flood - jednym z ataków typu DOS
# atak typu SYN to próba sparowania wielu (tysięcy, milionów) nowych połączeń TCP, połączenie takie wymaga porozumienia między klientem, a serwerem, tzw. TCP Handshake. Klient wysyła request SYN, a serwer odpowiada ACK, klient odpowiada ACK serwerowi i połączenie jest nawiązane. Atakujący może sprowokować wiele zapytań SYN klienta, aby zablokować serwer (który alokuje zasoby dla nowego połączenia)
iptables -A INPUT -p tcp -m state --state NEW -m limit --limit 5/second --limit-burst 2 -j ACCEPT

# pozwalamy na dostęp z interfejsu loopback, umożliwia to serwerowi dostep do samego siebie (localhost) unikamy w ten sposób problemów jakie miałyby aplikacje, które korzystają z takich zapytań chociażby w testach
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# nie chcemy blokować możliwości "ping-owania" serwera, może to być potrzebne do sprawdzenia czy jest on UP, ale ograniczamy ilość takich zapytań, blokujemy w ten sposób jeden kilka możliwych ataków, tzw. Smurf Attack, a także typu Ping of Death (ping flood), ICMP flood
iptables -N ICMP-RATE-LIMIT
iptables -A INPUT -m conntrack -p icmp --ctstate NEW -j ICMP-RATE-LIMIT

iptables -A ICMP-RATE-LIMIT -m limit --limit 1/minute --limit-burst 5 -j ACCEPT
iptables -A ICMP-RATE-LIMIT -j DROP

# zabezpieczamy się przed tzw. Pakietem XMAS, czyli takim który ma ustawione wszystkie możliwe flagi, pakiety takie powodują długi czas procesowania, w związku z tym blokują zasoby systemowe, istnieje także kilkanaście znanych błędnych kombinacji flag TCP w związku z tym blokujemy pakiety z ustawionymi takimi kombinacjami flag
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags FIN,RST RST,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP

# blokujemy połączenia z sieci lokalnych, szkodliwe zapytanie atakującego, lub podłączenia się pod sieć, może spowodować atak na nasz serwer z wewnątrz, oczekujemy połączeń od zewnętrznych klientów, blokujemy w ten sposób tzw. spoofing
iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP
iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP
iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP
iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP

# blokujemy błędne połączenia (które nie należą do nawiązanego połączenia TCP i nie są pakietami typu SYN, czyli nie są w trakcie nawiązywania połączenia)
iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP

# blokujemy wszystkie nowe połączenia TCP, które nie mają ustawionej flagi SYN, czyli nie są wcale nie chcą nawiązać nowego połączenia tylko są w jakiś sposób błędnie skonfigurowane, być może spreparowane przez atakującego
iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

# blokujemy połączenia o niestandardowych wartościach MSS - MSS czyli maximum segment size to parametr nagłówka TCP, który określa największą wartość danych w bajtach, które mogą być przesłane w jednym segmencie połączenia TCP (odpowiednik MTU Maximum Transmission Unit dla datagramów IP, aczkolwiek nie zlicza nagłówka)
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65536 -j DROP

# ponieważ nasz serwer będzie z reguły wystawiał aplikacje poprzez HTTP lub HTTPS możemy ograniczyć ruch do zezwolenia tylko na te porty, dodamy też obostrzenia uniemożliwiające zbyt dużą ilość połączeń
iptables -N HTTP-RATE-LIMIT

# przekierowujemy HTTP na osobny chain, wszystkie pozostałe połączenia będą zablokowane, dlatego te komendy sprawią, że tylko port 80, 8080 i 443 są otwarte
iptables -A INPUT -p tcp --dport 80 -j HTTP-RATE-LIMIT
iptables -A INPUT -p tcp --dport 8080 -j HTTP-RATE-LIMIT
iptables -A INPUT -p tcp --dport 443 -j HTTP-RATE-LIMIT

# blokujemy powyżej 80 połączeń z jednego IP, ta reguła jest krytyczna jeśli chodzi o zabezpieczenia przeciwko atakami typu DDoS gdzie atakujący po prostu w sposób teoretycznie legalny powoduje blokowanie serwera tzn. W momencie kiedy otwiera on zbyt wiele nowych połączeń, ale dokonujących standardowych czynności, np. Zapytania RESTowe, przeglądanie strony, nie możemy jednak pozwolić, aby pojedynczy użytkownik zapełnił całą pulę połączeń do serwera. Ciężko jednak określić górny próg który powinien być limitem, należy obserwować, czy aby przeciętni użytkownicy użytkujący aplikację w normalny sposób nie natrafili na błędy z powodu zbyt niskiego limitu, w takim przypadku należy go zwiększyć
iptables -A HTTP-RATE-LIMIT -p tcp -m connlimit --connlimit-above 80 --connlimit-mask 32 -j REJECT

# blokujemy zbyt dużą ilość nowych połączeń na sekundę, tutaj należy ustawić limit, dla którego zwykły użytkownik nie odczuje problemów z użytkowaniem, zablokowana zostanie jednak możliwość tworzenia masywnej liczby połączeń przez atakująćego
iptables -A HTTP-RATE-LIMIT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT
iptables -A HTTP-RATE-LIMIT -p tcp -m conntrack --ctstate NEW -j DROP

# wprowadzamy także rate limit dla ilości wysyłanych danych, ponad 150 pakietów na sekundę dla jednego połączenia będzie blokowanych
iptables -A HTTP-RATE-LIMIT -p tcp -m state --state NEW,RELATED,ESTABLISHED -m limit --limit 150/second --limit-burst 160 -j ACCEPT
# dodajemy odrzucanie połączeń, które przekroczyły podane limity
iptables -A HTTP-RATE-LIMIT -p tcp REJECT

# dodajemy dropowanie połączeń, których nie “whitelistujemy” nigdzie wyżej
iptables -A INPUT -p tcp -m state --state NEW DROP
