# UncleSurv //

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
$ sudo nano /etc/ssmtp/ssmtp.conf
...
UseSTARTTLS=YES
FromLineOverride=YES
mailhub=smtp.gmail.com:587
AuthUser=yourgmail_account@gmail.com
AuthPass=yourgmail_password
```
## Tree Structure
```java
unclersurv/
├── log/
│   ├── .fetch/
│   │   ├── .cust.load.rules
│   │   ├── .json.md5
│   │   ├── .list.mail
│   │   ├── .load.rules
│   │   ├── .log.md5
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
      "rule_chain_match": "DROP" },
   "setup_gmail": {
      "sender_alias": "Uncle Surv Admin",
      "target_addrs":["friend@gmail.com","mom@gmail.com","dad@gmail.com"],
      "mails_subjct": "Subject goes here",
      "mails_header": "Header goes here",
      "mails_footer": "Footer goes here"
   } 
}
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)
