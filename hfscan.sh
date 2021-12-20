#!/bin/sh

##############################
# */ script author: nowak */ #
# */  the recon is a art  */ # /* https://discord.gg/PePM2NR5zS ~/
#    */   v1.2.1-dev   /*    # /~ https://github.com/nowak0x01 */
# $/  hackingforce family #/ #
##############################


HELP="
$0 ({program}) ({options})

	$0 ffuf +options+
	$0 nmap +options+
	$0 wordgen +options+
	$0 zonetransfer +options+
	$0 dnslookup +options+
	$0 vhosts +options+
	$0 subdomains +options+
	$0 web-tecnology +options+
\n"

__defaultPATH="$PATH"
export PATH="/opt:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:$(grep $USER /etc/passwd | cut -d':' -f6)/go:$(grep $USER /etc/passwd | cut -d':' -f6)/local:$(grep $USER /etc/passwd | cut -d':' -f6):$PATH"

verify()
{
	local check=$1

	if [ "$(type -p $check)" = "" ];then

		printf "\n\e[1;31mERROR:\e[1;37m $check command \e[0mnot found in\e[1;37m $PATH \e[0m\n\n"
		export PATH="$__defaultPATH"
		exit 1

	fi
}

case "$1" in

	'ffuf'|'FFUF'|'fuff'|'FUFF')

		verify ffuf

		if [ "$4" == "" ];then

			printf "\n$0 %s [dir/files] [wordlist] [target]\n\n" "$1"
			export PATH="$__defaultPATH"
			exit 1

		fi

		# [ DEFAULT ] - EXTENSIONS='.yml,.yaml,.passwd,.conf,.php,.js,.html,.save,.swp,.bkp,.bak,.sql,.db,.ovpn,.md,.env,~,.json,.old,.log,.tar,.tar.gz,.gz,.tgz,.settings,.zip,.rar,.backup,.out,.info,.main,.master,.local,.inf,.git,.disabled,.dev,.default,.cnf,.cgi,.cer,.bin,.tmp,.temp'
		# [ ASP.NET/IIS ] - EXTENSIONS='.asp,.aspx,.cfg,.config,.zip,.xml,.svn,.svnignore,.web,.dll,.exe,.wasm,.wadl,.axd,.resx,.resouces,.wsdl,.xsd,.disco,.discomap,.config,.htm,.pdb,.ashx,.cs,.sln,.asax'
		# [ JAVA ] - EXTENSIONS='.jsp,.jsf,.xhtml,.xml,.class,.java,.jar,.seam,.faces,.shtml,.ifaces,.do,.action,.jspf,.properties'

		THREADS='110'
		EXTENSIONS='.yml,.yaml,.passwd,.conf,.php,.js,.html,.save,.swp,.bkp,.bak,.sql,.db,.ovpn,.md,.env,~,.json,.old,.log,.tar,.tar.gz,.gz,.tgz,.settings,.zip,.rar,.backup,.out,.info,.main,.master,.local,.inf,.git,.disabled,.dev,.default,.cnf,.cgi,.cer,.bin,.tmp,.temp'
		UAGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36 OPR/81.0.4196.60'

		if [[ "$2" == "DIR" || "$2" == "dir" ]];then

			printf "\n\e[1;37m{#} TARGET:\e[1;32m $4 \e[1;37m| WORDLIST:\e[1;32m $3 \e[1;37m| METHOD:\e[1;32m (DIR - DEFAULT) {#}\e[0m\n\n"
			ffuf -ic -recursion -D -w $3 -u $4 -H "User-Agent: $UAGENT" -c -t $THREADS --timeout 16 -mc all -ac

		elif [[ "$2" == "files" || "$2" == "FILES" ]];then

			printf "\n\e[1;37m{#} TARGET:\e[1;32m $4 \e[1;37m| WORDLIST:\e[1;32m $3 \e[1;37m| METHOD:\e[1;32m (FILES - DEFAULT) {#}\e[0m\n\n"
			ffuf -ic -w $3 -u $4 -H "User-Agent: $UAGENT" -c -e "$EXTENSIONS" -t $THREADS --timeout 16 -mc all -ac

			cut -d'.' -f1 $3 | sort -u > /var/tmp/files-wordlist-changed.recon
			printf "\n\e[1;37m{#} TARGET:\e[1;32m $4 \e[1;37m| WORDLIST:\e[1;32m /var/tmp/files-wordlist-changed.recon \e[1;37m| METHOD:\e[1;32m (FILES - CHANGED) #}\e[0m\n\n"
			ffuf -ic -w /var/tmp/files-wordlist-changed.recon -u $4 -H "User-Agent: $UAGENT" -c -e "$EXTENSIONS" -t $THREADS --timeout 16 -mc all -ac

		fi

		;;

	'nmap'|'NMAP')

		verify nmap

		if [ "$3" == "" ];then

			printf "\n$0 %s [ctf/world] [target]\n\n" "$1"
			export PATH="$__defaultPATH"
			exit 1

		fi

		if [[ "$2" == "ctf" || "$2" == "CTF" ]];then

			SYN_scan="-sSVC -Pn -T4 --min-rate 10000 -p-"
			TCP_scan="-sTVC -Pn -T4 --min-rate 10000 -p-"
			UDP_scan="-sUV -Pn -T4 --min-rate 10000 -p-"

			printf "\n\e[1;37m{#} starting the scan \e[1;32m(CTF - syn) \e[1;37m{#}\n\n"
			nmap $SYN_scan $3

			printf "\n\e[1;37m{#} starting the scan \e[1;32m(CTF - udp) \e[1;37m{#}\n\n"
			nmap $UDP_scan $3

			printf "\n\e[1;37m{#} starting the scan \e[1;32m(CTF - tcp) \e[1;37m{#}\n\n"
			nmap $TCP_scan $3

		elif [[ "$2" == "world" || "$2" == "WORLD" ]];then

			SYN_scan="-sS -Pn -T2 -D RND:126 -g 80 -p-"
			TCP_scan="-sT -Pn -T2 -D RND:126 -g 80 -p-"
			UDP_scan="-sUV -Pn -T2 -D RND:126 -g 80 -p-"

			printf "\n\e[1;37m{#} starting the scan \e[1;32m(WORLD - syn) \e[1;37m{#}\n\n"
			$SYN_scan $3

			printf "\n\e[1;37m{#} starting the scan \e[1;32m(WORLD - udp) \e[1;37m{#}\n\n"
			$UDP_scan $3

			printf "\n\e[1;37m{#} starting the scan \e[1;32m(WORLD - tcp) \e[1;37m{#}\n\n"
			$TCP_scan $3

		fi

		;;

	'wg'|'wordgen'|'WG'|'WORDGEN')

		if [ "$3" == "" ];then

			printf "\n$0 %s [wordlist] [common words ( separated by ',' )]\n
	{example}\n
		$0 %s ./large-files.txt 'corpsec,sec,corp'
\n" "$1" "$1"

			export PATH="$__defaultPATH"
			exit 1

		fi

		function add_word()
		{
			local argv=$1
			printf "%s$1%s\n" "$_generate_" "$(head -n$_quant_ recon.words.quant | tail -1)" >> custom-wordlist.recon
			printf "%s$1%s\n" "$(head -n$_quant_ recon.words.quant | tail -1)" "$_generate_" >> custom-wordlist.recon
		}

		rm -f custom-wordlist.recon
		printf $3 > recon.words
		tr ',' '\n' < recon.words > recon.words.quant

		spin='-\|/'
		printf "\n\e[1;32m{+}\e[1;37m Generating the custom Wordlist \e[1;32m{+}\e[1;37m\n\n"

		for _quant_ in $(seq 1 `wc -l recon.words.quant|cut -d' ' -f1`);do

			for _generate_ in $(cut -d'.' -f1 $2);do

				add_word -
				add_word .
				add_word _

				i=$(( (i+1) %4 ))
				printf "\r${spin:$i:1}"


			done
		done

		printf "\n\e[1;32m{+}\e[1;37m Custom Wordlist generated! \e[1;32m{+}\e[1;37m\n"
		printf "\e[1;32m%s \e[0m\n\n" "`ls -gG $PWD/custom-wordlist.recon | awk '{print $1, $3, $6, $7}'`"

		rm -f recon.words.quant recon.words

		;;

	'ZN'|'zn'|'zonetransfer'|'ZONETRANSFER')

			verify host

			if [ $# -ne 2 ];then

				printf "\n$0 $1 [host]\n\n"

			else

				printf "\n\e[0m[//\e[1;32m+\e[0m//] \e[1;32mName Servers \e[0m[//\e[1;32m+\e[0m//]\n\n";host -t ns $2|cut -d" " -f4
				printf "\n\e[1;37m::::::::::::::::::::::::::::::::::\n"

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

			printf "\n$0 $1 [host]\n\n"

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

		UAGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36 OPR/81.0.4196.60'
		etc_hosts='127.0.0.1 localhost'

		if [ $# -ne 5 ];then
			printf "\n$0 $1 [host] [wordlist] [http/https] [ip]\n\n"

		elif [ "$(id -u)" != "0" ];then
			printf "\n\e[1;31mERROR:\e[0m only root!\n\n"

		elif [ ! -f $3 ];then
			printf "\n\e[1;31mERROR:\e[0m wordlist: %s not found\n\n" "$2"

		elif ! [[ "$4" == "http" || "$4" == "https" ]];then
			printf "\n\e[1;31mERROR:\e[0m only http or https\n\n"

		else


			[ ! "$(grep -E '$5|$2' /etc/hosts)" == "0" ] && printf "\n%s %s " "$5" "$2" >> /etc/hosts

			printf "\n\e[1;32m=>\e[0m Searching VHOSTS on:\e[1;37m %s://%s/ \e[1;32m<=\e[0m\n\n" "$4" "$2"
			ffuf -u $4://$2/ -H "Host: FUZZ.$2" -H "User-Agent: $UAGENT" -ac -ic -c -t 300 -noninteractive -s --timeout 23 -mc all -w $3 > $PWD/vhosts.$2

			_dSize="$(curl -sk $4://$2|wc -c)"

			for _vCurl in $(cat $PWD/vhosts.$2);do
				printf "%s.%s " "$_vCurl" "$2" >> $PWD/vhosts.$2_curl
			done

			cp /etc/hosts /etc/hosts.bkp
			printf "%s" "$etc_hosts" > /etc/hosts
			printf "\n%s %s " "$5" "$2" >> /etc/hosts
			tr '\n' ' ' < $PWD/vhosts.$2_curl >> /etc/hosts

			for _vHost in $(cat $PWD/vhosts.$2);do

				if ! [[ "$(curl -m 5 -sk $4://$_vHost.$2 | wc -c)" == "0" || "$(curl -m 5 -sk $4://$_vHost.$2 | wc -c)" == "$_dSize" ]];then
					printf ":::: host-> %s :::: \e[1;32m200 OK\e[0m\n" "$4://$_vHost.$2/" | tee -a $PWD/vhosts.$2.size
				fi
			done

			if [ ! -f $PWD/vhosts.$2.size ];then

				printf "\n::::\e[1;32m NO VHOSTS FOUND\e[0m ::::\n\n"
				rm -f vhosts*
				export PATH="$__defaultPATH"
				exit 1
			fi

			cut -d '/' -f3 $PWD/vhosts.$2.size > $PWD/vhosts.$2.valids
			cp /etc/hosts /etc/hosts.bkp
			printf "%s" "$etc_hosts" > /etc/hosts
			printf "\n%s %s " "$5" "$2" >> /etc/hosts
			tr '\n' ' ' < $PWD/vhosts.$2.valids >> /etc/hosts

			printf "\n\e[1;32m::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\e[0m\n\n%s\n\n\e[1;32m::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\e[0m\n\n" "$(cat /etc/hosts)"

		fi

		rm -f vhosts*

		;;


	'subdomain'|'subdomains'|'SUBDOMAIN'|'SUBDOMAINS'|'sub'|'SUB')

		verify subfinder

		if [ $# -ne 2 ];then

			printf "\n$0 $1 [host]\n\n"

		else

			subfinder -all -recursive -nW -o hfscan_subdomains.subfinder -d $2

		fi

		;;


	'web-tecnology'|'web'|'WEB'|'WEB-TECNOLOGY'|'httpx'|'HTTPX')

		verify httpx

		if [ $# -ne 2 ];then

			printf "\n$0 $1 [targets-wordlist]\n\n"
			export PATH="$__defaultPATH"
			exit 1

		elif [ ! -f $2 ];then

			printf "\n\e[1;31mERROR:\e[0m targets-wordlist not found!\n\n"
			export PATH="$__defaultPATH"
			exit 1

		else

			printf "\n\e[1;32m:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\e[0m\n\n"
			httpx -l $2 -silent -follow-redirects -status-code -tech-detect -web-server -ip -cname -cdn -method -ports 80,443,8080,8000,3000,3333,9001,22,2222 -websocket -o hfscan_webtecnology.httpx
			printf "\n\e[1;32m:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::\e[0m\n\n"

		fi

		;;


	*)
		printf "$HELP"
		export PATH="$__defaultPATH"
		exit 1
		;;
esac

export PATH="$__defaultPATH"
