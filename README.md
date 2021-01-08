# UncleSurv // (n). underclosesurveillance

UncleSurv ( Under Close Surveillance ) is a simple bash-based program that is designated to prevent DoS threat, which is specialized for ICMP Flood attack. The program itself has 2 modes that are adapted from IDS and IPS functionality, so it may detect, notify, and deflect the potential threat based on the parameter that has been set up on a JSON file.

The decision method will be taken from the client's ping activity toward the machine/server. When the sequence reaches the max parameter, the program will automatically call out the client's IP to be issued with IPTABLES for further management of its connection. User can also add their own rules manually that later to be also added to the saved logs, so it will automatically load the rules whenever the program is about to run.

UncleSurv has not made it into the deb packages yet :3, therefore, you can either clone the repository or simply download the zip format. Some packages and config are also mandatory for the program to be able to work properly, which including so setup your ssmtp service for the sender's Gmail account.

## Dependencies
```bash
$ git clone https://github.com/hotpotcookie/unclesurv.git
$ cd unclesurv/
```
```bash
$ wget https://github.com/hotpotcookie/unclesurv/archive/main.zip
$ unzip main.zip -d unclesurv
$ cd unclesurv/
```
```bash
$ sudo apt-get install jq libphp-phpmailer rsyslog ssmtp -y
```
```bash
$ sudo nano /etc/ssmtp/ssmtp.conf
...
UseSTARTTLS=YES
FromLineOverride=YES
mailhub=smtp.gmail.com:587
AuthUser=yourgmail_account@gmail.com
AuthPass=yourgmail_password
```
## Tree Structure
```bash
unclersurv/
├── log/
│   ├── .fetch/
│   │   ├── .cust.load.rules
│   │   ├── .json.md5
│   │   ├── .list.mail
│   │   ├── .load.rules
│   │   ├── .log.md5
│   │   ├── .log.rules
│   │   ├── .rules.md5
│   │   ├── .tmp.mail
│   │   └── .tmp.rules
│   ├── Dec.30.2020.db
│   ├── Dec.31.2020.db
│   └── ...
├── source/
│   ├── run-addrules-cust.sh
│   ├── run-addrules.sh
│   ├── run-backg.sh
│   ├── run-foreg.sh
│   └── run-init.sh
├── main.sh
├── packages.lst
└── setup.json
```
## JSON
```json
{
   "setup_rule": {
      "max_ping_attempt": 20,
      "disable_protocol": ["tcp","icmp","udp"],
      "disable_tcp_port": [80,8080,22,443],
      "disable_udp_port": [53],
      "detection_method": "ip",
      "rule_chain_match": "DROP" 
   },
   "setup_gmail": {
      "sender_alias": "Uncle Surv Admin",
      "target_addrs": ["friend@gmail.com","mom@gmail.com","dad@gmail.com"],
      "mails_subjct": "Subject goes here",
      "mails_header": "Header goes here",
      "mails_footer": "Footer goes here"
   } 
}
```
## Main Program
```bash
$ sudo bash main.sh start ## [start/restart/stop/clear]
...
:: Preparing internal directory ...      [3/3]
:: Loading recent iptables rules ...
:: Restarting rsyslog daemon ...
:: Initiating program ...
:: Redirecting to main interface ...
...
unclesurv 1.3.2              01/05/21 08:47:39 AM
-------------------------------------------------
[1]      ADD NEW RULES  |  UPDATE PARAMETER   [5]
[2]  VIEW ACTIVE RULES  |  VIEW PROCESSES     [6]
[3]    RESET ALL RULES  |  CLEAR SCREEN       [7]
[4]          VIEW LOGS  |  EXIT               [8]
-------------------------------------------------
>>
```
```bash
>> 1
--
:: CURRENT RULESET : iptables -A INPUT -s 192.168.100.0/24 -d 192.168.200.100 -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j DROP
:: CURRENT RULESET : iptables -A INPUT -s 192.168.100.0/24 -d 192.168.200.100 -p tcp --dport 8080 -m conntrack --ctstate NEW,ESTABLISHED -j DROP
:: CURRENT RULESET : iptables -A INPUT -s 192.168.100.0/24 -d 192.168.200.100 -p tcp --dport 3128 -m conntrack --ctstate NEW,ESTABLISHED -j DROP
:: CURRENT RULESET : iptables -A INPUT -s 192.168.100.0/24 -d 192.168.200.100 -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j DROP
:: CURRENT RULESET : iptables -A INPUT -s 192.168.100.0/24 -d 192.168.200.100 -p tcp --dport 21 -m conntrack --ctstate NEW,ESTABLISHED -j DROP
--
:: CONFIRM TO ADD RULESET TO IPTABLES (y) ? y
:: Adding all ruleset ...
```
```bash
>> 2
--
:: IP ADDR : 172.23.123.121/20
:: IPTABLES RULESET
--
-P INPUT ACCEPT
-A INPUT -s 192.168.100.0/24 -d 192.168.200.100/32 -p tcp -m tcp --dport 21 -m conntrack --ctstate NEW,ESTABLISHED -j DROP
-A INPUT -s 192.168.100.0/24 -d 192.168.200.100/32 -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j DROP
-A INPUT -s 192.168.100.0/24 -d 192.168.200.100/32 -p tcp -m tcp --dport 3128 -m conntrack --ctstate NEW,ESTABLISHED -j DROP
-A INPUT -s 192.168.100.0/24 -d 192.168.200.100/32 -p tcp -m tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j DROP
-A INPUT -s 192.168.100.0/24 -d 192.168.200.100/32 -p tcp -m tcp --dport 8080 -m conntrack --ctstate NEW,ESTABLISHED -j DROP
--
-P OUTPUT ACCEPT
--
-P FORWARD ACCEPT
```
```bash
>> 3
--
:: Flushing iptables ...
:: Overwritting log/.fetch/.tmp.rules ...
:: Overwritting log/.fetch/.load.rules ...
:: Overwritting log/.fetch/.cust.load.rules ...
:: Overwritting log/.fetch/.list.mail ...
```
```bash
>> 4
--
:: LISTING : log/
--
Dec.22.2020.db   Dec.24.2020.db   Dec.26.2020.db   Dec.29.2020.db   Dec.31.2020.db   Jan.1.2021.log  Jan.3.2021.log  Jan.5.2021.log
Dec.22.2020.log  Dec.24.2020.log  Dec.26.2020.log  Dec.29.2020.log  Dec.31.2020.log  Jan.2.2021.db   Jan.4.2021.db
Dec.23.2020.db   Dec.25.2020.db   Dec.28.2020.db   Dec.30.2020.db   Dec.31.2021.log  Jan.2.2021.log  Jan.4.2021.log
Dec.23.2020.log  Dec.25.2020.log  Dec.28.2020.log  Dec.30.2020.log  Jan.1.2021.db    Jan.3.2021.db   Jan.5.2021.db
--
:: ENTER FILENAME : Jan.4.2021.db
----------------------------------------------------------------------------------------------------------------------
MAC ADDR                                  | SOURCE ADDR     | TARGET ADDR     | PROTOCOL | SEQ             | STAT
----------------------------------------------------------------------------------------------------------------------
00:15:5d:19:89:55:00:15:5d:99:bc:44:08:00 | 172.23.112.1    | 172.23.117.251  | ICMP     | 14 ATTEMPT(S)   | --
00:15:5d:19:89:55:00:15:5d:c5:8b:a5:08:00 | 172.23.112.1    | 172.23.117.251  | ICMP     | 4 ATTEMPT(S)    | --
----------------------------------------------------------------------------------------------------------------------
```
```bash
>> 5
--
:: LISTING : setup.json
--
1 | setup_rule
2 | setup_gmail
--
:: CHOOSE SECTION   : 1
:: INSERT KEY NAME  : max_ping_attempt
:: INSERT NEW VALUE : 35
```
```bash
>> 6
--
 PPID   PID  PGID   SID TTY      TPGID STAT   UID   TIME COMMAND
    0     1     0     0 ?           -1 Sl       0   0:04 /init
    1     7     7     7 ?           -1 Ss       0   0:00 /init
    7     8     7     7 ?           -1 S        0   0:00  \_ /init
    8     9     9     9 pts/0     9982 Ss    1000   0:00      \_ -bash
    9  9982  9982     9 pts/0     9982 S+       0   0:00      |   \_ sudo ./main.sh start
 9982  9992  9982     9 pts/0     9982 S+       0   0:00      |       \_ /bin/bash ./main.sh start
 9992 10059  9982     9 pts/0     9982 S+       0   0:00      |           \_ sudo bash source/run-backg.sh
10059 10061  9982     9 pts/0     9982 S+       0   1:47      |           |   \_ bash source/run-backg.sh
10061 31944  9982     9 pts/0     9982 S+       0   0:00      |           |       \_ bash source/run-backg.sh
31944 31945  9982     9 pts/0     9982 R+       0   0:00      |           |           \_ sudo cat /var/log/syslog
31944 31946  9982     9 pts/0     9982 S+       0   0:00      |           |           \_ tail -n 1
31944 31947  9982     9 pts/0     9982 S+       0   0:00      |           |           \_ cut -c 1-6
31944 31948  9982     9 pts/0     9982 S+       0   0:00      |           |           \_ tr -s   .
 9992 10818  9982     9 pts/0     9982 S+       0   0:00      |           \_ sudo bash source/run-foreg.sh
10818 10824  9982     9 pts/0     9982 S+       0   0:00      |               \_ bash source/run-foreg.sh
10824 31918  9982     9 pts/0     9982 R+       0   0:00      |                   \_ ps axjf
    8 10053 10053 10053 ?           -1 Ssl    104   0:58      \_ /usr/sbin/rsyslogd
```
## Contribution
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change. Please make sure to update tests as appropriate.
