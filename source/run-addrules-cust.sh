#!/bin/bash
#--------------------------
# jia2f adalah custom IDS/IPS yang dapat mengantisipasi ancaman dari potensi attacker
# seperti penggunaan ping-flood, port scan, serta failure-attempt pada service seperti SSH
#--------------------------
# o MAIN RUN (BACKGROUND)
#--------------------------
if [[ -s "log/.fetch/.cust.load.rules"	]]
then
	uniq_rules=$(sudo cat log/.fetch/.cust.load.rules | sort | uniq)
	cat /dev/null > "log/.fetch/.cust.load.rules"
	echo "$uniq_rules" > "log/.fetch/.cust.load.rules"
	sudo iptables -F
fi
if [[ -s "log/.fetch/.cust.load.rules" ]]
then
	while IFS= read -r get_line
	do
		if [[ $get_line ]]
		then
			check_sect=$(echo -e "$get_line" | cut -c 1 | uniq)
			case $check_sect in
				"!")	
						chain=$(echo -e "$get_line" | cut -c 3- | tr -s '\t' '#' | cut -d '#' -f 1)
						ip_source=$(echo -e "$get_line" | cut -c 3- | tr -s '\t' '#' | cut -d '#' -f 2)
						ip_destination=$(echo -e "$get_line" | cut -c 3- | tr -s '\t' '#' | cut -d '#' -f 3)
						proto=$(echo -e "$get_line" | cut -c 3- | tr -s '\t' '#' | cut -d '#' -f 4)
						port=$(echo -e "$get_line" | cut -c 3- | tr -s '\t' '#' | cut -d '#' -f 6)
						rule=$(echo -e "$get_line" | cut -c 3- | tr -s '\t' '#' | cut -d '#' -f 7)
						sudo iptables $chain $ip_source $ip_destination $proto --dport $port -m conntrack --ctstate NEW,ESTABLISHED $rule
						;;
				"@")	
						chain=$(echo -e "$get_line" | cut -c 3- | tr -s '\t' '#' | cut -d '#' -f 1)
						ip_source=$(echo -e "$get_line" | cut -c 3- | tr -s '\t' '#' | cut -d '#' -f 2)
						ip_destination=$(echo -e "$get_line" | cut -c 3- | tr -s '\t' '#' | cut -d '#' -f 3)
						proto=$(echo -e "$get_line" | cut -c 3- | tr -s '\t' '#' | cut -d '#' -f 5)
						rule=$(echo -e "$get_line" | cut -c 3- | tr -s '\t' '#' | cut -d '#' -f 4)						
						sudo iptables $chain $ip_source $ip_destination $proto $rule
						;;
			esac
		fi
	done < "log/.fetch/.cust.load.rules"
fi
rules_check=$(sudo iptables -L -n -v | grep UNCLE)
if [[ $rules_check == '' ]]
then
	get_rule=$(cat log/.fetch/.log.rules)
	sudo iptables $get_rule
fi


#    "JSON_README_SETUP_PARAM":
#    {
#        "max_ping_attempt": "number of maximum count of target that allowed to ping, i.e 20. format NUMERIC",
#        "disable_protocol": "protocol to be disabled when ping reach its maximum, i.e icmp, udp, and tcp. format STRING ARRAY",
#        "disable_tcp_port": "tcp port to be blocked when tcp protocol is selected to be disabled, i.e 80, 443, and 23. format NUMERIC ARRAY",
#        "disable_udp_port": "udp port to be blocked when udp protocol is selected to be disabled. i.e 53. format NUMERIC ARRAY",
#        "detection_method": "ways for iptables rule to specify the source, i.e ip or mac. format STRING",
#        "rule_chain_match": "ways for iptables to chain the rule for executiion, i.e DROP, ALLOW, FORWARD, or REJECT. format STRING"
#    },
