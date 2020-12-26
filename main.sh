#!/bin/bash
#--------------------------
# jia2f adalah custom IDS/IPS yang dapat mengantisipasi ancaman dari potensi attacker
# seperti penggunaan ping-flood, port scan, serta failure-attempt pada service seperti SSH
#--------------------------
# o MAIN RUN
#--------------------------
if [[ "$UID" -eq "0" ]]
then
	case $1 in
		"start")
			sudo bash source/run-init.sh
			sudo bash source/run-backg.sh &
			echo -e "\n[DONE]: Initiating program ..."; sleep 2;			
			;;
		"stop")
			sudo pkill -f "sudo bash source/run-backg.sh"
			sudo iptables -F
			sudo cat /dev/null > "log/.fetch/.tmp.rules"
			;;
		"restart")
			sudo pkill -f "sudo bash source/run-backg.sh"
			sudo iptables -F
			sudo cat /dev/null > "log/.fetch/.tmp.rules"
			sudo bash source/run-init.sh
			sudo bash source/run-backg.sh &
			echo -e "\n[DONE]: Initiating program ..."; sleep 2;			
			;;
		"clear")
			sudo iptables -F
			sudo cat /dev/null > "log/.fetch/.tmp.rules"
			sudo cat /dev/null > "log/.fetch/.load.rules"			
			;;
	esac
else
	echo -e "[INFO]: Program requires root permission ..."
	echo -e "[EXIT]: Exitting program ..."
	exit 0
fi
