#!/bin/bash
main() #class main
{
 clear
 loop="true"
 while [ $loop == "true" ]
 do
 ############# Feature program ############
 echo "Main Menu"
 echo "1. Status layanan iptables"
 echo "2. Membuat firewall dengan iptables"
 echo "3. Melihat log jaringan"
 echo "4. Exit"
 echo -n "Pilihan anda: "
 read opt_main
 case $opt_main in
  1) checkstatus ;;
  2) buildfirewall ;;
  3) ;;
  4) exit 0 ;;
  *) read -p "Pilihan anda tidak tersedia!!"
     main ;;
  esac
 done
}

checkstatus()
{
  clear
  loop="true"
  while [ $loop == "true" ]
  do
  echo ""
  echo "Layanan Iptables "
  echo "1. Implementasi aturan iptables"
  echo "2. Flush iptables (Menggapus/menghilangkan seluruh aturan iptables)"
  echo "3. Main Menu"
  echo -n "Pilihan anda: "
  read opt_checkstatus
  case $opt_checkstatus in
   1) sudo iptables -L -v
      read -p "Press any key"
      checkstatus;;
   2) sudo iptables -F
      echo "Proses berhasil dilakukan"
      read -p "Press any key"
      checkstatus;;
   3) main;;
   *) read -p "Pilihan anda tidak tersedia!!"
      checkstatus;;
   esac
  done
}

buildfirewall()
{
  clear
  ###############Implementasi aturan yang akan di buat############
  echo "Peraturan yang akan di buat akan berlaku di ?"
  echo "1. INPUT/INCOME" #Aturan ini akan berlaku untuk jaringan dari luar mencoba akses ke jaringan lokal
  echo "2. OUTPUT/OUTGOING" #Aturan ini akan berlaku untuk jaringan lokal yang akan mencoba akses jaringan luar/internet
  echo "3. Forward" #Aturan ini mengizinkan jaringan lokal/internet untuk bypass aturan yang telah di implementasikan
  echo -n "Pilihan anda: "
  read opt_ch
  if [ ! -z $opt_ch ]
  then
   case $opt_ch in
   1) chain="INPUT"
      S_ipaddress;;
   2) chain="OUTPUT"
      S_ipaddress;;
   3) chain="FORWARD"
      S_ipaddress;;
   *) read -p "Pilihan anda tidak tersedia!!"
      buildfirewall;;
  esac
  else
  read -p "Pilihan anda tidak boleh kosong!!"
      buildfirewall
  fi
}

S_ipaddress()
{
  clear
  echo ""
  #########Source IP Address##########
  echo "Informasi tambahan untuk source/sumber IP Address"
  echo "1. Membuat Firewall pada single source IP Address"
  echo "2. Membuat Firewall pada source subnet IP Address"
  echo -n "Pilihan anda: "
  read opt_ip
  if [ ! -z $opt_ip ]
  then
  case $opt_ip in
  1) echo -n "Masukan IP Address: "
     read ip_source
     if [ ! -z $ip_source ] #kalo bisa dia detect isi variable sama bolehin angka doang
     then
     	echo "IP Address berhasil terisi"
     	D_ipaddress
     else
     	echo "IP Address belum terisi!!"
     	S_ipaddress
     fi
     ;;
  2) echo -n "Masukan subnet IP Address(contoh: 192.168.10.0/24): "
     read ip_source
     if [ ! -z $ip_source ] #kalo bisa dia detect isi variable sama bolehin angka doang
     then
     	echo "IP Address berhasil terisi"
     	D_ipaddress
     else
     	echo "IP Address belum terisi!!"
     	S_ipaddress
     fi
     ;;
  *) read -p "Pilihan anda tidak tersedia !!"
     S_ipaddress;;
  esac
  else
    read -p "Pilihan anda tidak boleh kosong!!"
    S_ipaddress
  fi
}

D_ipaddress()
{
  clear
  #########Tujuan akses IP Address##########
  echo "Informasi tambahan untuk tujuan akses pada sumber IP Address"
  echo "1. Membuat Firewall pada single destination IP Address"
  echo "2. Membuat Firewall pada subnet destination IP Address"
  echo -n "Pilihan anda: "
  read opt_ipD
  if [ ! -z $opt_ipD ]
  then
  case $opt_ipD in
  1) echo -n "Masukan IP Address: "
     read ip_destination
     if [ ! -z $ip_destination ] #kalo bisa dia detect isi variable sama bolehin angka doang
     then
     	echo "IP Address berhasil terisi"
     	protocol
     else
     	echo "IP Address belum terisi!!"
     	D_ipaddress
     fi
     ;;
  2) echo -n "Masukan subnet IP Address(contoh: 192.168.10.0/24): "
     read ip_destination
     if [ ! -z $ip_destination ] #kalo bisa dia detect isi variable sama bolehin angka doang
     then
     	echo "IP Address berhasil terisi"
     	protocol
     else
     	echo "IP Address belum terisi!!"
     	D_ipaddress
     fi
     ;;
  *) read -p "Pilihan anda tidak tersedia !!"
     D_ipaddress;;
  esac
  else
    read -p "Pilihan anda tidak boleh kosong!!"
    D_ipaddress
  fi
}

protocol()
{
  clear
  ###############Protocol#############
  echo "Jenis Protokol yang akan digunakan"
  echo "1. Memblokir seluruh layanan TCP"
  echo "2. Memblokir layanan TCP tertentu"
  echo "3. Memblokir port tertentu" 
  echo "4. Tidak menggunakan protokol"
  echo -n "Pilihan anda: "
  read proto_ch
  if [ ! -z $proto_ch ]
  then
  case $proto_ch in
  1) proto=TCP
     echo "Proses berhasil dilakukan"
     read -p "Press any key"
     rule
     ;;
  2) echo -n "Masukkan Nama Layanan TCP(huruf kapital): "
     read proto
     if [ ! -z $proto ] #kalo bisa dia detect isi variable sama bolehin huruf kapital
     then
     	echo "Protokol yang telah di pilih berhasil terisi"
     	rule
     else
     	echo "Protokol belum terisi!!"
     	protocol
     fi
     ;;
  3) echo -n "Masukkan Nama Port(huruf kapital): "
     read proto_ch
     if [ ! -z $proto_ch ] #kalo bisa dia detect isi variable sama bolehin huruf kapital
     then
     	echo "Layanan port berhasil terisi"
     	rule
     else
     	echo "Layanan port belum terisi!!"
     	protocol
     fi
     ;;
  4) proto="NULL"
     echo "Proses berhasil dilakukan"
     read -p "Press any key"
     rule
     ;;
  *) read -p "Pilihan anda tidak tersedia !!"
     protocol;;
  esac
  else
    read -p "Pilihan anda tidak boleh kosong!!"
    protocol
  fi
}

rule()
{
   clear
   #############Aturan implementasi hak izin############# 
   echo "Implementasi aturan pada penerimaan koneksi/packet ?"
   echo "1. Menerima koneksi/packet"
   echo "2. Menolak koneksi/packet" #client bakal tahu kalo koneksi dia kaga keterima.
   echo "3. Menghapus koneksi/packet" #client ga bakal tahu keadaan packet terkirim ke server karena server tidak membalas permintaan, 
   					#dia langgsung menghapus permintaan tersebut.
   echo "4. Log"					
   echo -n "Pilihan anda: "
   read rule_ch
   if [ ! -z $rule_ch ]
   then
   case $rule_ch in
   1) rule="ACCEPT"
      echo "Proses berhasil dilakukan"
      read -p "Press any key"
      generate_rule
      ;;
   2) rule="REJECT"
      echo "Proses berhasil dilakukan"
      read -p "Press any key"
      generate_rule
      ;;
   3) rule="DROP"
      echo "Proses berhasil dilakukan"
      read -p "Press any key"
      generate_rule
      ;;
   4) rule="LOG"
      echo "Proses berhasil dilakukan"
      read -p "Press any key"
      generate_rule
      ;;
   *) read -p "Pilihan anda tidak tersedia !!"
      protocol;;
   esac
   else
     read -p "Pilihan anda tidak boleh kosong!!"
     protocol
   fi
}

generate_rule()
{
   ###################Proses membuat aturan####################
   echo "Implementasi aturan yang dimasukan ke dalam iptables"
   echo "Aturan yang akan di implementasikan: "
   if [ $proto == "NULL" ]
   then
   echo "Iptables -A $chain -s $ip_source -d $ip_destination -j $rule"
   gen=1
   else
   echo "Iptables -A $chain -s $ip_source -d $ip_destination -p $proto -j $rule"
   gen=2
   fi
   echo "Informasi aturan tersebut akan di implementasikan ke dalam iptables? Yes=1, No=2"
   echo -n "Pilihan anda: "
   read yesno
   if [ $yesno == 1 ] && [ $gen == 1 ]; then
   sudo iptables -A $chain -s $ip_source -d $ip_destination -j $rule
   echo "Proses berhasil dilakukan"
   read -p "Press any key"
   main
   else if [ $yesno == 1 ] && [ $gen == 2 ]; then
   sudo iptables -A $chain -s $ip_source -d $ip_destination -p $proto -j $rule
   echo "Proses berhasil dilakukan"
   read -p "Press any key"
   main         
   else if [ $yesno == 2 ]; then
   main
   fi
   fi
   fi
}
main
