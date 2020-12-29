#!/bin/bash
#--------------------------
# jia2f adalah custom IDS/IPS yang dapat mengantisipasi ancaman dari potensi attacker
# seperti penggunaan ping-flood, port scan, serta failure-attempt pada service seperti SSH
#--------------------------
# o MAIN RUN (BACKGROUND)
#--------------------------
if [[ -s "log/.fetch/.load.rules" ]]
then
	uniq_rules=$(sudo cat log/.fetch/.load.rules | sort | uniq)
	cat /dev/null > "log/.fetch/.load.rules"
	echo "$uniq_rules" > "log/.fetch/.load.rules"
fi
if [[ -s "log/.fetch/.load.rules" ]]
then
	while IFS= read -r get_line
	do
		if [[ $get_line ]]
		then		
			IFS=$'\t'
			read -a arr_rule <<< "$get_line"
			if [[ ${#arr_rule[@]} -gt 3 ]]
			then
				check_rule=$(sudo iptables -S INPUT | grep "${arr_rule[0]}" | grep "${arr_rule[1]}" | grep "${arr_rule[4]}")
				if [[ ! $check_rule ]]
				then
					sudo iptables -A INPUT -s ${arr_rule[0]} -p ${arr_rule[1]}  --dport ${arr_rule[4]} -m conntrack --ctstate NEW,ESTABLISHED -j ${arr_rule[2]}
				fi
			else
				check_rule=$(sudo iptables -S INPUT | grep "${arr_rule[0]}" | grep "${arr_rule[1]}")
				if [[ ! $check_rule ]]
				then
					sudo iptables -A INPUT -s ${arr_rule[0]} -p ${arr_rule[1]} -j ${arr_rule[2]}
				fi
			fi
		fi
	done < "log/.fetch/.load.rules"
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
