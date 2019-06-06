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