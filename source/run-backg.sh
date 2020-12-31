#!/bin/bash
#--------------------------
# jia2f adalah custom IDS/IPS yang dapat mengantisipasi ancaman dari potensi attacker
# seperti penggunaan ping-flood, port scan, serta failure-attempt pada service seperti SSH
#--------------------------
# o MAIN RUN (BACKGROUND)
#--------------------------

IFS=$'\n'
date_year=$(date +'%Y')	
file_prefix=$(sudo cat /var/log/syslog | tail -n 1 | cut -c 1-6 | tr -s ' ' '.')
regx_prefix=$(sudo cat /var/log/syslog | tail -n 1 | cut -c 1-6)	

max_param=$(jq '.setup_param.max_ping_attempt' setup.json)
rule_param=$(jq '.setup_param.rule_chain_match' setup.json | cut -d '"' -f 2)
detect_param=$(jq '.setup_param.detection_method' setup.json | cut -d '"' -f 2)
proto_param=$(jq '.setup_param.disable_protocol[]' setup.json | cut -d '"' -f 2)
tcp_param=$(jq '.setup_param.disable_tcp_port[]' setup.json | cut -d '"' -f 2)
udp_param=$(jq '.setup_param.disable_udp_port[]' setup.json | cut -d '"' -f 2)
mail_sbj=$(jq '.setup_gmail.mails_subjct' setup.json | cut -d '"' -f 2)
mail_hdr=$(jq '.setup_gmail.mails_header' setup.json | cut -d '"' -f 2)
mail_ftr=$(jq '.setup_gmail.mails_footer' setup.json | cut -d '"' -f 2)
mail_add=$(jq '.setup_gmail.target_addrs[]' setup.json | cut -d '"' -f 2)
arr_proto=("$proto_param")
arr_tcp=("$tcp_param")
arr_udp=("$udp_param")
arr_mail=("$mail_add")

grep -a "UNCLE" /var/log/syslog | grep -a "$regx_prefix" > "log/$file_prefix.$date_year.log"
curr_md5=$(md5sum "log/$file_prefix.$date_year.log" | cut -d ' ' -f 1)
curr_md5_2=$(md5sum "setup.json" | cut -d ' ' -f 1)	
curr_md5_3=$(md5sum "log/.fetch/.load.rules" | cut -d ' ' -f 1)
load_md5=$(cat "log/.fetch/.log.md5")
load_md5_2=$(cat "log/.fetch/.json.md5")
load_md5_3=$(cat "log/.fetch/.rules.md5")

while :
do
	date_year=$(date +'%Y')	
	file_prefix=$(sudo cat /var/log/syslog | tail -n 1 | cut -c 1-6 | tr -s ' ' '.')
	regx_prefix=$(sudo cat /var/log/syslog | tail -n 1 | cut -c 1-6)

	grep -a "UNCLE" /var/log/syslog | grep -a "$regx_prefix" > "log/$file_prefix.$date_year.log"
	curr_md5=$(md5sum "log/$file_prefix.$date_year.log" | cut -d ' ' -f 1)
	load_md5=$(cat "log/.fetch/.log.md5")

	if [[ $curr_md5 != $load_md5 || $curr_md5_2 != $load_md5_2 || $curr_md5_3 != $load_md5_3 ]]
	then
		cat /dev/null > "log/$file_prefix.$date_year.db"
		cat /dev/null > "log/.fetch/.tmp.mail"
		echo $curr_md5 > "log/.fetch/.log.md5"
		echo $curr_md5_2 > "log/.fetch/.json.md5"
		echo $curr_md5_3 > "log/.fetch/.rules.md5"
		curr_md5=$(md5sum "log/$file_prefix.$date_year.log" | cut -d ' ' -f 1)
		curr_md5_2=$(md5sum "setup.json" | cut -d ' ' -f 1)	
		curr_md5_3=$(md5sum "log/.fetch/.load.rules" | cut -d ' ' -f 1)		
		load_md5=$(cat "log/.fetch/.log.md5")
		load_md5_2=$(cat "log/.fetch/.json.md5")
		load_md5_3=$(cat "log/.fetch/.rules.md5")		
		echo    "----------------------------------------------------------------------------------------------------------------------" >> "log/$file_prefix.$date_year.db"		
		printf "%-41s | %-15s | %-15s | %-8s | %-15s | %-7s\n" "MAC ADDR" "SOURCE ADDR" "TARGET ADDR" "PROTOCOL" "SEQ" "STAT" >> "log/$file_prefix.$date_year.db"
		echo    "----------------------------------------------------------------------------------------------------------------------" >> "log/$file_prefix.$date_year.db"

		IFS=$'\n'
		raw_mac=$(cat "log/$file_prefix.$date_year.log" | cut -d '=' -f 4 | cut -d ' ' -f 1 | sort | uniq -d)
		raw_ptc=$(cat "log/$file_prefix.$date_year.log" | cut -d '=' -f 12 | cut -d ' ' -f 1 | sort | uniq -d)
		arr_mac=("$raw_mac")
		for i_mac in ${arr_mac[@]}
		do
			raw_src=$(cat "log/$file_prefix.$date_year.log" | grep "$i_mac" | cut -d '=' -f 5 | cut -d ' ' -f 1 | sort | uniq -d)
			arr_src=("$raw_src")
			for i_src in ${arr_src[@]}
			do
				timeinc=$(cat "log/$file_prefix.$date_year.log" | grep "$i_mac" | grep "$i_src" | wc -l)
				raw_dst=$(cat "log/$file_prefix.$date_year.log" | grep "$i_mac" | grep "$i_src" | cut -d '=' -f 6 | cut -d ' ' -f 1 | sort | uniq -d)
				arr_dst=("$raw_dst")

				if [[ $timeinc -ge $max_param ]]
				then
					stat="$rule_param"
					if [[ $stat == 'DROP' ]]
					then
						stat+='P'
					fi
					stat+="ED"
				else
					check_stat=$(cat log/.fetch/.load.rules | tr -s '\t' ' ' | cut -d ' ' -f 1 | sort | uniq | grep $i_src)
					if [[ $check_stat ]]
					then
						stat="$rule_param"
						if [[ $stat == 'DROP' ]]
						then
							stat+='P'
						fi						
						stat+="ED"
					else
						stat="--"
					fi
				fi
				for i_dst in ${arr_dst[@]}
				do
					printf "%-41s | %-15s | %-15s | %-8s | %-15s | %-7s\n" "$i_mac" "$i_src" "$i_dst" "$raw_ptc" "$timeinc ATTEMPT(S)" "$stat" >> "log/$file_prefix.$date_year.db"
				done

				if [[ $stat != "--" ]] ## PERBAIKIN STATT DARI RULES
				then
					if [[ $detect_param == "ip" ]]
					then
						check_rule=$(sudo iptables -S INPUT | grep "$i_src")
						if [[ ! $check_rule || $check_rule ]]
						then
							check_mail=$(cat log/.fetch/.list.mail | grep "$i_mac" | grep "$i_src")
							if [[ ! $check_mail ]]
							then
								curr_date=$(date +'%D %T %p')								
								#echo "$i_mac" >> "log/.fetch/.list.mail"
								echo -e "Subject: $mail_sbj | $i_src\n\n::" >> "log/.fetch/.tmp.mail"
								echo -e "$curr_date\n$mail_hdr\n::" >> "log/.fetch/.tmp.mail"
								echo -e "Source MAC Address: $i_mac" >> "log/.fetch/.tmp.mail"
								echo -e "Source IP Address: $i_src" >> "log/.fetch/.tmp.mail"
								echo -e "Server IP Address: $i_dst" >> "log/.fetch/.tmp.mail"
								echo -e "Protocol Detection: $raw_ptc" >> "log/.fetch/.tmp.mail"
								echo -e "Sequence Requests: $timeinc attempts out of $max_param at max\n::" >> "log/.fetch/.tmp.mail"
							fi
							for i_ptc in ${arr_proto[@]}
							do
								case $i_ptc in
									"tcp")
										if [[ $arr_tcp ]]
										then
											for p_tcp in ${arr_tcp[@]}
											do
												#sudo iptables -A INPUT -s $i_src -p $i_ptc --dport $p_tcp -m conntrack --ctstate NEW,ESTABLISHED -j $rule_param
												echo -e "$file_prefix.$date_year\t$i_src\t$i_ptc\t$rule_param\tPORT $p_tcp" >> "log/.fetch/.tmp.rules"
												echo -e "$i_src\t$i_ptc\t$rule_param\tPORT\t$p_tcp" >> "log/.fetch/.load.rules"
												if [[ ! $check_mail ]]
												then
													echo -e "$i_src $i_ptc $rule_param PORT $p_tcp" >> "log/.fetch/.tmp.mail"
												fi
											done
											continue
										fi
										;;
									"udp")
										if [[ $arr_udp ]]
										then
											for p_udp in ${arr_udp[@]}
											do
												#sudo iptables -A INPUT -s $i_src -p $i_ptc --dport $p_udp -m conntrack --ctstate NEW,ESTABLISHED -j $rule_param
												echo -e "$file_prefix.$date_year\t$i_src\t$i_ptc\t$rule_param\tPORT $p_udp" >> "log/.fetch/.tmp.rules"
												echo -e "$i_src\t$i_ptc\t$rule_param\tPORT\t$p_udp" >> "log/.fetch/.load.rules"
												if [[ ! $check_mail ]]
												then
													echo -e "$i_src $i_ptc $rule_param PORT $p_udp" >> "log/.fetch/.tmp.mail"
												fi
											done
											continue
										fi
										;;
								esac
								#sudo iptables -A INPUT -s $i_src -p $i_ptc -j $rule_param
								echo -e "$file_prefix.$date_year\t$i_src\t$i_ptc\t$rule_param" >> "log/.fetch/.tmp.rules"
								echo -e "$i_src\t$i_ptc\t$rule_param" >> "log/.fetch/.load.rules"
								if [[ ! $check_mail ]]
								then
									echo -e "$i_src $i_ptc $rule_param" >> "log/.fetch/.tmp.mail"
								fi					
							done
							## baca .savedrules goes here & gapake tanggal tanggalan
							sudo bash source/run-addrules.sh														
							if [[ ! $check_mail ]]
							then
								echo -e "::\nPlease checkout log/$file_prefix.$date_year.log and log/$file_prefix.$date_year.db. $mail_ftr" >> "log/.fetch/.tmp.mail"
								echo -e "\nSincerly,\nUncleSurv" >> "log/.fetch/.tmp.mail"
								echo -e "$i_mac\t$i_src" >> "log/.fetch/.list.mail"
								for i_mailadd in ${arr_mail[@]}
								do
									nohup sudo sendmail $i_mailadd < "log/.fetch/.tmp.mail"  &> /dev/null &
									wait $!
								done
							fi
						fi
					fi					
				fi
			done
		done
		echo    "----------------------------------------------------------------------------------------------------------------------" >> "log/$file_prefix.$date_year.db"
	fi
done

## jq '.whitelist.ip[]' setup.json | cut -d '"' -f 2
## jq '.setup_param.max_ping_attempt' setup.json
## delete rule : sudo iptables -S INPUT | grep 'LOG' | cut -c 4-
##			   : sudo iptables -D [rule]
## insert rule : sudo iptables -A INPUT -s $ip_source -d $ip_destination -p $proto -j $rule

## tcp port : sudo iptables -A INPUT -s 172.27.144.1 -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j DROP
## for loop
##	tcp >> tcp_port
##	udp >> udp_port