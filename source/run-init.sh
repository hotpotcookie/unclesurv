#!/bin/bash
#--------------------------
# jia2f adalah custom IDS/IPS yang dapat mengantisipasi ancaman dari potensi attacker
# seperti penggunaan ping-flood, port scan, serta failure-attempt pada service seperti SSH
#--------------------------
# o PRE-REQUESITES CHECK
#--------------------------
pth_arr=("log" "source" "log/.fetch")
arr_len=${#pth_arr[@]}
echo -ne ":: Preparing internal directory ...      "
for i in `seq 0 $arr_len`; do echo -ne "[$i/$arr_len]"'\r\t\t\t\t\t '; sleep 0.5; done;
for idx in ${pth_arr[@]}
do
	if [[ ! -d $idx ]]
	then
		mkdir $idx
	fi
done

touch "log/.fetch/.log.md5"
touch "log/.fetch/.json.md5"
touch "log/.fetch/.rules.md5"
touch "log/.fetch/.tmp.rules"
touch "log/.fetch/.load.rules"
touch "log/.fetch/.tmp.mail"
touch "log/.fetch/.list.mail"
touch "log/.fetch/.cust.load.rules"

arr_len=${#pkg_arr[@]}
rules_check=$(sudo iptables -L -n -v | grep UNCLE)
if [[ $rules_check == '' ]]
then
	sudo iptables -I INPUT -p icmp --icmp-type echo-request -j LOG --log-prefix "LOGGING_PING_UNCLESURV"
fi

curr_md5=$(md5sum "setup.json" | cut -d ' ' -f 1)
load_md5=$(cat "log/.fetch/.json.md5")

echo -ne "\n:: Loading recent iptables rules ..."; sleep 0.5;
sudo bash source/run-addrules.sh
sudo bash source/run-addrules-cust.sh

echo -ne "\n:: Restarting rsyslog daemon ..."; sleep 0.5;
nohup sudo service rsyslog restart &> /dev/null &
wait $!