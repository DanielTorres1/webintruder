#!/bin/bash
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
RESET='\e[0m'


function print_ascii_art {
cat << "EOF"
                                                     					
					https://github.com/DanielTorres1

EOF
}


print_ascii_art

echo -e "$OKBLUE [+] Instalando WEB Intruder $RESET" 

echo -e "$OKGREEN [+] Instalando librerias perl necesarias $RESET" 

sudo cp cpanm /usr/bin 
sudo cp webintruder.pl /usr/bin/

mkdir /usr/share/webintruder 2>/dev/null
sudo cp -R payloads /usr/share/webintruder

sudo chmod a+x /usr/bin/cpanm
sudo chmod a+x /usr/bin/webintruder.pl

cd webintruder/ 
sudo cpan .
