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
		"stop")
			sudo pkill -f "sudo bash source/run-backg.sh"
			sudo iptables -F
			sudo cat /dev/null > "log/.fetch/.tmp.rules"
			;;
		"restart"|"start")
			sudo pkill -f "sudo bash source/run-backg.sh"
			sudo iptables -F
			sudo cat /dev/null > "log/.fetch/.tmp.rules"
			sudo bash source/run-init.sh
			sudo bash source/run-backg.sh &
			echo -e "\n:: Initiating program ..."; sleep 0.5;
			echo -e ":: Redirecting to main interface ..."; sleep 1.5;
			sudo bash source/run-foreg.sh
			;;
		"clear")
			sudo iptables -F
			sudo cat /dev/null > "log/.fetch/.tmp.rules"
			sudo cat /dev/null > "log/.fetch/.load.rules"
			sudo cat /dev/null > "log/.fetch/.list.mail"
			;;
		*|"help")
			echo -e "available options: start / restart / stop / clear / help"
			;;
	esac
else
	echo -e "[INFO]: Program requires root permission ..."
	echo -e "[EXIT]: Exitting program ..."
	exit 0
fi
