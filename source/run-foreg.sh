#!/bin/bash
#--------------------------
# jia2f adalah custom IDS/IPS yang dapat mengantisipasi ancaman dari potensi attacker
# seperti penggunaan ping-flood, port scan, serta failure-attempt pada service seperti SSH
#--------------------------
# o MAIN RUN (BACKGROUND)
#--------------------------
main() #class main
{
	while :
	do
		############# Feature program ############		
		clear		
		curr_date=$(date +'%D %T %p')
		echo "unclesurv 1.3.2              $curr_date"
		echo "-------------------------------------------------"
		echo "[1]      ADD NEW RULES  |  UPDATE PARAMETER   [5]"		
		echo "[2]  VIEW ACTIVE RULES  |  VIEW PROCESSES     [6]"
		echo "[3]    RESET ALL RULES  |  CLEAR SCREEN       [7]"
		echo "[4]          VIEW LOGS  |  EXIT               [8]"
		echo "-------------------------------------------------"
		while :
		do
			read -p ">> " opt_main
			case $opt_main in
				1) meth_addrule;; 	5) meth_updateparam;;
				2) meth_checkstat;;	6) meth_viewproc;;
				3) meth_resetrule;; 7) break;;
				4) meth_viewlog;;	8) meth_exit;;
			esac
		done
	done
}
meth_resetrule()
{
	sudo iptables -F
	sudo cat /dev/null > "log/.fetch/.tmp.rules"
	sudo cat /dev/null > "log/.fetch/.load.rules"
	sudo cat /dev/null > "log/.fetch/.cust.load.rules"	
	sudo cat /dev/null > "log/.fetch/.list.mail"	
	echo -e "--\n:: Flushing iptables ..."
	echo -e ":: Overwritting log/.fetch/.tmp.rules ..."
	echo -e ":: Overwritting log/.fetch/.load.rules ..."	
	echo -e ":: Overwritting log/.fetch/.cust.load.rules ..."		
	echo -e ":: Overwritting log/.fetch/.list.mail ...\n"		
}
meth_viewlog() {
	echo -e "--\n:: LISTING : log/\n--"
	ls log/
	echo "--"
	read -p ":: ENTER FILENAME : " view_file
	cat log/$view_file
	echo ""
}
meth_exit() {
	echo -e "--\n:: Running service in background ..."
	echo -e ":: Exitting program ..."
	exit 0
}
meth_viewproc()
{
	echo "--"
	ps axjf
	echo ""
}
meth_updateparam()
{
	echo -e "--\n:: LISTING : setup.json\n--"
	echo -e "1 | setup_rule"
	echo -e "2 | setup_gmail\n--"
	read -p ":: CHOOSE SECTION : " opt_json
	if [[ $opt_json ]]
	then
		case $opt_json in
			1)	jq '.setup_rule' setup.json
				;;
			2)	jq '.setup_gmail' setup.json
				;;
		esac			
		echo -e "--"
		read -p ":: INSERT KEY NAME  : " sec_entry
		read -p ":: INSERT NEW VALUE : " new_entry
		case $opt_json in
			1)	if [[ $sec_entry && $new_entry ]]
				then
					exec_jq=$(jq '.setup_rule.'"$sec_entry"' = '"$new_entry"'' setup.json)
					if [[ $exec_jq ]]
					then
						echo "$exec_jq" > setup.json
					fi
				fi
				;;
			2)	if [[ $sec_entry && $new_entry ]]
				then
					exec_jq=$(jq '.setup_gmail.'"$sec_entry"' = '"$new_entry"'' setup.json)
					if [[ $exec_jq ]]
					then
						echo "$exec_jq" > setup.json
					fi
				fi
				;;
		esac
	fi
	echo ""
}
meth_checkstat()
{
	ip_srv=$(ip a | grep inet | grep eth | cut -c 10- | cut -d ' ' -f 1)
	echo -e "--\n:: IP ADDR : $ip_srv\n:: IPTABLES RULESET\n--"
	sudo iptables -S INPUT ; echo "--"
	sudo iptables -S OUTPUT ; echo "--"
	sudo iptables -S FORWARD ; echo -e "--\n"	
}
meth_addrule()
{
	chain=""; ip_source=""; ip_destination=""; port=""; proto=""; rule="";
	###############Implementasi aturan yang akan di buat############
	echo -e "--\n1 | INPUT/INCOME" #Aturan ini akan berlaku untuk jaringan dari luar mencoba akses ke jaringan lokal
	echo "2 | OUTPUT/OUTGOING" #Aturan ini akan berlaku untuk jaringan lokal yang akan mencoba akses jaringan luar/internet
	echo -e "3 | FORWARD\n--" #Aturan ini mengizinkan jaringan lokal/internet untuk bypass aturan yang telah di implementasikan
	read -p ":: SPECIFY CHAIN FOR THE CONNECTION : " opt_ch
	if [ ! -z $opt_ch ]
	then
		case $opt_ch in
			1)	chain="-A INPUT"
				S_ipaddress;;
			2)	chain="-A OUTPUT"
				S_ipaddress;;
			3)	chain="-A FORWARD"
				S_ipaddress;;
		esac
	fi
}
S_ipaddress()
{
	#########Source IP Address##########
	echo -e "--\n1 | CREATE RULES FOR SINGLE SOURCE IP ADDRESS"
	echo -e "2 | CREATE RULES FOR SUBNET SOURCE NETWORK ADDRESS"
	echo -e "3 | CREATE RULES FOR ALL SOURCE ADDRESS\n--"
	read -p ":: SPECIFY SOURCE ADDRESS OPTION : " opt_ip
	if [ ! -z $opt_ip ]
	then
		case $opt_ip in
			1)	echo -n ":: INSERT SOURCE IP ADDRESS      : "
				read ip_source
				if [ ! -z $ip_source ] #kalo bisa dia detect isi variable sama bolehin angka doang
				then
					D_ipaddress
				fi
				;;
			2)	echo -n ":: INSERT SOURCE NETWORK ADDRESS (192.168.10.0/24) : "
				read ip_source
				if [ ! -z $ip_source ] #kalo bisa dia detect isi variable sama bolehin angka doang
				then
					D_ipaddress
				fi
				;;
			3)	ip_source='all'
				D_ipaddress
				;;
		esac
	fi
}
D_ipaddress()
{
	#########Tujuan akses IP Address##########
	echo -e "--\n1 | CREATE RULES FOR SINGLE DESTINATION IP ADDRESS"
	echo -e "2 | CREATE RULES FOR SUBNET DESTINATION NETWORK ADDRESS"
	echo -e "3 | CREATE RULES FOR ALL DESTINATION ADDRESS\n--"
	read -p ":: SPECIFY DESTINATION ADDRESS OPTION : " opt_ipD
	if [ ! -z $opt_ipD ]
	then
		case $opt_ipD in
		1)	echo -n ":: INSERT DESTINATION IP ADDRESS      : "
			read ip_destination
			if [ ! -z $ip_destination ] #kalo bisa dia detect isi variable sama bolehin angka doang
			then
				protocol
			fi
			;;
		2)	echo -n ":: INSERT DESTINATION NETWORK ADDRESS (192.168.10.0/24) : "
			read ip_destination
			if [ ! -z $ip_destination ] #kalo bisa dia detect isi variable sama bolehin angka doang
			then
				protocol
			fi
			;;
		3) 	ip_destination='all'
			protocol
			;;
		esac
	fi
}
protocol()
{
	###############Protocol#############
	echo -e "--\n1 | APPLY RULE ON SPESIFIC PROTOCOL (TCP/UDP/ICMP)"
	echo -e "2 | APPLY RULE TO ALL PROTOCOL\n--"
	echo -n ":: SPECIFY PROTOCOL OPTION : "
	read proto_ch
	if [ ! -z $proto_ch ]
	then
		case $proto_ch in
		1) 	read -p ":: INSERT PROTOCOL         : " proto
			proto=$(echo "$proto" | tr '[:upper:]' '[:lower:]')
			if [[ $proto == 'tcp' || $proto == 'udp' ]]
			then
				read -p ":: INSERT $proto PORT         : " port
			fi
			rule
			;;
		2)	proto="all"
			rule
			;;
		esac
	fi
}
rule()
{
	#############Aturan implementasi hak izin############# 
	echo -e "--\n1 | ACCEPT CONNECTION/PACKET"
	echo "2 | REJECT CONNECTION/PACKET" #client bakal tahu kalo koneksi dia kaga keterima.
	echo -e "3 | DROP CONNECTION/PACKET\n--" #client ga bakal tahu keadaan packet terkirim ke server karena server tidak membalas permintaan,	dia langgsung menghapus permintaan tersebut. 
	echo -n ":: SPECIFY RULE'S POLICY : "
	read rule_ch
	if [ ! -z $rule_ch ]
	then
		case $rule_ch in
			1) 	rule="-j ACCEPT"
				generate_rule
				;;
			2) 	rule="-j REJECT"
				generate_rule
				;;
			 3) rule="-j DROP"
				generate_rule
				;;
		esac
	fi
}
generate_rule()
{
	###################Proses membuat aturan####################
	if [[ $ip_source == "all" ]]
	then
		ip_source=" "
	else
	 	ip_source="-s $ip_source"
	fi
	if [[ $ip_destination == "all" ]]
	then
	 	ip_destination=" "
	else
	 	ip_destination="-d $ip_destination"
	fi
	if [[ $proto == "all" ]]
	then
	 	proto=" "
	else
	 	proto="-p $proto"
	fi
	if [[ $port ]]
	then
		IFS=' '
		read -a arr_port <<< "$port"	 	
		inc=0
		echo "--"				 
		for i in ${arr_port[@]}
		do
			echo -e ":: CURRENT RULESET : iptables $chain $ip_source $ip_destination $proto --dport $i -m conntrack --ctstate NEW,ESTABLISHED $rule"
		done
		echo "--"
	else
		echo -e "--\n:: CURRENT RULESET : iptables $chain $ip_source $ip_destination $proto $rule"
	fi
	read -p ":: CONFIRM TO ADD RULESET TO IPTABLES (y) ? " confirm_opt
	if [[ $confirm_opt == 'y' || $confirm_opt == 'Y' ]]
	then
		echo -e ":: Adding all ruleset ..."
		if [[ $port ]]
		then
			for i in ${arr_port[@]}
			do
				#sudo iptables $chain $ip_source $ip_destination $proto --dport $i -m conntrack --ctstate NEW,ESTABLISHED $rule
				echo -e "! $chain\t$ip_source\t$ip_destination\t$proto\tPORT\t$i\t$rule" >> "log/.fetch/.cust.load.rules"				
			done		
		else
			#sudo iptables $chain $ip_source $ip_destination $proto $rule
			echo -e "@ $chain\t$ip_source\t$ip_destination\t$rule\t$proto" >> "log/.fetch/.cust.load.rules"			
		fi
		sudo bash source/run-addrules-cust.sh
	fi
	echo ""
}
main
