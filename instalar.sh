#!/bin/bash
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
RESET='\e[0m'


function print_ascii_art {
cat << "EOF"
                                                     					
 __        __   _       ___       _                  _           
 \ \      / /__| |__   |_ _|_ __ | |_ _ __ _   _  __| | ___ _ __ 
  \ \ /\ / / _ \ '_ \   | || '_ \| __| '__| | | |/ _` |/ _ \ '__|
   \ V  V /  __/ |_) |  | || | | | |_| |  | |_| | (_| |  __/ |   
    \_/\_/ \___|_.__/  |___|_| |_|\__|_|   \__,_|\__,_|\___|_|                                                                    

				https://github.com/DanielTorres1

EOF
}


print_ascii_art

echo -e "$OKBLUE [+] Instalando WEB Intruder $RESET" 

echo -e "$OKGREEN [+] Instalando librerias perl necesarias $RESET" 

sudo cp webintruder.pl /usr/bin/

mkdir /usr/share/webintruder 2>/dev/null
sudo cp -R payloads /usr/share/webintruder

sudo chmod a+x /usr/bin/webintruder.pl

cd webintruder/ 
sudo cpan .
