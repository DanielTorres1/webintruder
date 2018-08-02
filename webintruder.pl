#!/usr/bin/perl
use Data::Dumper;
use XML::Simple;
use Time::localtime;
use Getopt::Std;
use Term::ANSIColor qw(:constants);
use MIME::Base64 qw( decode_base64 );
use webintruder;
no warnings;



$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0; 
my $t = localtime;
my $today = sprintf("%04d-%02d-%02d",$t->year + 1900, $t->mon + 1, $t->mday);

my $debug = 0; 
my $json =0; 

sub banner
{
	print '               _    _____       _                  _           '."\n";
	print '              | |  |_   _|     | |                | |          '."\n";
	print ' __      _____| |__  | |  _ __ | |_ _ __ _   _  __| | ___ _ __ '."\n";
	print ' \ \ /\ / / _ \ |_ \ | | | |_ \| __|  __| | | |/ _` |/ _ \  __|'."\n";
	print '  \ V  V /  __/ |_) || |_| | | | |_| |  | |_| | (_| |  __/ |   '."\n";
	print '   \_/\_/ \___|_.__/_____|_| |_|\__|_|   \__,_|\__,_|\___|_|   v1.0'."\n";
	print "\n";
	print "Autor: Daniel Torres\n";
	print "\n";
}

sub usage
{  
	banner;
  printf "Uso :\n";                                                                   
  printf "webintruder.pl -f file.xml -t {session/sqli/error/overflow/repeat}  -c cookie \n\n";  
  printf "webintruder.pl -f file.xml -t sqli \n"; 
  printf "webintruder.pl -f file.xml -t repeat -p list.txt \n";
  printf "webintruder.pl -f file.xml -t overflow \n";
  printf "webintruder.pl -f file.xml -t error \n";
  printf "webintruder.pl -f file.xml -t session -c \"PHPSESSION=hfs77fhsuf7\" \n";
  printf "webintruder.pl -f file.xml -t session -c \"PHPSESSION=0\" \n";
  printf "webintruder.pl -f file.xml -t session -c nocookie \n";
  printf "webintruder.pl -f file.xml -t lfi -o {linux/windows} \n";
  printf "webintruder.pl -f file.xml -t login -u root -p passwords.txt \n";
  
  exit(1);
}


getopts('f:t:c:o:p:h:u:q:', \%opts);

my $file = $opts{'f'} if $opts{'f'};
my $testType = $opts{'t'} if $opts{'t'};
my $passFile = $opts{'p'} if $opts{'p'};
my $cookie = $opts{'c'} if $opts{'c'};
my $os = $opts{'o'} if $opts{'o'};
my $user = $opts{'u'} if $opts{'u'};
my $quiet = $opts{'q'} if $opts{'q'};

my $section = $file;
$section =~ s/\..*//s; # extract filename


# Print help message if required
if ($opts{'h'} || !(%opts)) {
	usage();
	exit 0;
}  
if ($quiet ne 1)
  {banner;}

system("mkdir -p log/$testType 2>/dev/null ");

if ($testType eq "session")
	{$title = "COOKIE";}
else	
	{$title = "PARAMETROS";}

open (SALIDA,">$section-$testType.csv") || die "ERROR: No puedo abrir el fichero $testType.csv\n";
print SALIDA "ID;$url;MÉTODO;$title;ESTADO ORIGINAL;ESTADO ACTUAL;¿COINCIDEN?;ERROR EN LA RESPUESTA;LONGITUD DE LA RESPUESTA\n";
close (SALIDA);	
		
################### Load URLs ####################
my $xml = new XML::Simple;

# read accounts XML file
$request_xml = $xml->XMLin($file, ForceArray=>['item']);
$request_number = @{$request_xml->{item}}; 
if ($testType eq "session")
	{print GREEN,"[+] Testeando con la cookie = $cookie \n\n ", RESET;}
	
if ($testType eq "sqli" || $testType eq "overflow" || $testType eq "error" || $testType eq "lfi")
	{
	my $payloads_count=`cat /usr/share/webintruder/payloads/$testType$os.txt | wc -l`;		
	$payloads_count =~ s/\n//g; 	
	print GREEN,"[+] Payloads: $payloads_count (/usr/share/webintruder/payloads/$testType$os.txt) \n ", RESET; 
	}
	
print GREEN,"[+] Tipo de test: $testType \n", RESET; 	
print GREEN,"[+] Tenemos $request_number peticion(es) \n ", RESET;    

######################################################

my $webintruder = webintruder->new(	debug => $debug, 
					proxy_host => '',
					proxy_port => '',
					proxy_user => '',
					proxy_pass => '');
					
my $req_id=0;

for (my $i=0; $i<$request_number;$i++)
{
     
   my $url = $request_xml->{item}->[$i]->{url};     
   my $method = $request_xml->{item}->[$i]->{method};      
   my $original_status = $request_xml->{item}->[$i]->{status};  
   my $original_response64 = $request_xml->{item}->[$i]->{response}->{content};   
   my $request = decode_base64($request_xml->{item}->[$i]->{request}->{content});
   
   
   
   my $new_request_parameters;
   print YELLOW,"[+] Método $method ; Petición $i ($url) \n ", RESET;  
       
   
   my $current_headers = $webintruder->headers;
   #print "request $request \n";   
   
  my @headers_array = split("\r\n\r\n",$request);
    
  $headers = @headers_array[0];
  $request_parameters = @headers_array[1]; #POST params
   
   
   ########## procesar los headers ##########
   my @headers_array2 = split("\n",$headers);
   foreach (@headers_array2)
   {
	  if (! ($_ =~ /POST|GET|Host|Content-Length|Connection/m)){	# No me interesa estos headers 
		  
		   my @array = split(": ",$_);
		   my $header_name = @array[0];
		   my $header_value = @array[1];		  
		   $header_value =~ s/\n//g; 
		   $header_name =~ s/\n//g; 
		   $header_value =~ s/\r//g; 
		   
		   
		   if ($testType eq "session" || $cookie ne "")
		   {		   
			
				if ($header_name eq "Cookie")
				{ 
					if ($cookie ne "nocookie")
						{$current_headers->header($header_name => $cookie);}
				}
				else
					{$current_headers->header($header_name => $header_value);}		   
		   }
		   else		   		  
		   {		   
			   $current_headers->header($header_name => $header_value);
		   }   
		}	 	 
   }
   ##############################
   
   if ($method eq "GET")  
   {
	   	my @url_array = split('\?',$url);
		$url = @url_array[0];
		$request_parameters = @url_array[1];		
   }
   
   print "url $url \n";
   print	"request_parameters ($request_parameters) \n" if ($debug); 
	   ################ acceder a todas las variables POST/GET #####################
	   	   
    if($request_parameters =~ /{/m){
	#JSON request	
	print BLUE,"\t[+] Peticion JSON detectada \n ", RESET;  
	$json = 1;
	my %name_value_array;	     
	my @parameters_array = split(',',$request_parameters);
	foreach my $param (@parameters_array)
		{								
			$param =~ s/"|{|}//g; 
			my @param_array = split(':',$param);
			my $param_name = @param_array[0];
			my $param_value = @param_array[1];		
			push @name_value_array, { $param_name => $param_value};
		} 
    }
    else
    {
		# Peticion POST normal
		my %name_value_array;	     
		my @parameters_array = split('&',$request_parameters);
		foreach my $param (@parameters_array)
		{						
			my @param_array = split('=',$param);
			my $param_name = @param_array[0];
			my $param_value = @param_array[1];		
			push @name_value_array, { $param_name => $param_value};
		}
	}
    
    	   	   
	# @name_value_array contiene:
	# $VAR1 = {
          #'searchword' => 'sss'
        #};
	#$VAR2 = {
          #'ordering' => undef
        #};
		
				
	###########################
	   
	################ session 	#######################   
	if ($testType eq "session")
	{	  
		$webintruder->request(url =>$url, method => $method, headers=> $current_headers, original_status => $original_status, original_response64 => $original_response64, test => $testType, section => $section, request_parameters => $final_request_parameters,req_id => $req_id, cookie => $cookie);
		$req_id++;
	}
	
	################ repeat  #######################   
	if ($testType eq "repeat")
	{	  			
		open (MYINPUT,"<$passFile") || die "ERROR: Can not open the file $passFile\n";						
		while ($inject=<MYINPUT>)
		{ 
			# Get request
			$inject =~ s/\n//g; 				
			$final_url = $url;			
			$final_url =~ s/INJECT/$inject/g; 					
			
			# Post request
			$final_request_parameters = $request_parameters;			
			$final_request_parameters =~ s/INJECT/$inject/g;
			#
			
			print "final_url $final_url \n" if ($debug);
		    $webintruder->request(url => $final_url, method => $method, headers=> $current_headers, original_status => $original_status, original_response64 => $original_response64, test => $testType, section => $section, request_parameters => $final_request_parameters,req_id => $req_id);
			$req_id++;																			
		}
		close MYINPUT;
	}
	
	
	################ login  #######################   
	if ($testType eq "login")
	{	  			
		open (MYINPUT,"<$passFile") || die "ERROR: Can not open the file $passFile\n";						
		while ($password=<MYINPUT>)
		{ 
			# Get request
			$password =~ s/\n//g; 				
			$final_url = $url;			
			$final_url =~ s/USUARIO/$user/g;
			$final_url =~ s/PASSWORD/$password/g;
			
			
			
			# Post request
			$final_request_parameters = $request_parameters;			
			$final_request_parameters =~ s/USUARIO/$user/g;
			$final_request_parameters =~ s/PASSWORD/$password/g;
			#
			
			print "final_url $final_url \n" if ($debug);
		    $webintruder->request(url => $final_url, method => $method, headers=> $current_headers, original_status => $original_status, original_response64 => $original_response64, test => $testType, section => $section, request_parameters => $final_request_parameters,req_id => $req_id);
			$req_id++;																			
		}
		close MYINPUT;
	}
	
	
	   
	################ sqli 	#######################      
	if ($testType eq "sqli")
	{		    
		if ($method eq "GET" && $request_parameters eq "") # la variable esta al finalizar la $url https://dominio.com.bo/Usuarios/Usuario/12
		{
			print BLUE,"\t[+] Peticion con parametros concatenados a la URL detectada \n ", RESET;  			
			my $last_char = substr $url, -1;  # last word			
			my $url_inject = "";
			# https://dominio.com.bo/Usuarios/Usuario/index.php/	---> https://dominio.com.bo/Usuarios/Usuario/index.php/INJECT
			if ($last_char eq "/")
			{
				$url_inject = $url."INJECT";
			}
			else
			{
			  # https://dominio.com.bo/Usuarios/Usuario/12	---> https://dominio.com.bo/Usuarios/Usuario/INJECT			  
			  my @url_array = split('/',$url);
			  $len = $#url_array;

			  for (my $i=0;$i<=$len; $i++)
			  {
				  
				if ($i ne $len)
					{$url_inject = $url_inject.@url_array[$i]."/";}
				else
					{$url_inject .= "INJECT";}
			  }
			}#end else

			print "url_inject $url_inject \n" if ($debug);
			######### send 	request https://dominio.com.bo/Usuarios/Usuario/'INJECT
			open (MYINPUT,"</usr/share/webintruder/payloads/sqli.txt") || die "ERROR: Can not open the file /usr/share/webintruder/payloads/sqli.txt\n";						
			while ($inject=<MYINPUT>)
			{ 
				$inject =~ s/\n//g; 
				$final_url = $url_inject; 
				$final_url =~ s/INJECT/$inject/g; 					
				
				##post
				$final_request_parameters = $new_request_parameters; 
				#print "request_parameter2 $final_request_parameters \n" if ($debug);
				$final_request_parameters =~ s/INJECT/$inject/g; 						
				######
						
				print "final_url $final_url \n" if ($debug);
				$webintruder->request(url => $final_url, method => $method, headers=> $current_headers, original_status => $original_status, original_response64 => $original_response64, test => $testType, section => $section, request_parameters => $final_request_parameters,req_id => $req_id);
				$req_id++;														
						
			}
			close MYINPUT;
				#################################################
		}#end GET
		   			  
	    
		#POST/GET 	parameters
		#print Dumper @name_value_array;
		foreach my $hash_ref (@name_value_array) {					
			foreach my $param1 (keys %{$hash_ref}) {														
				print BLUE,"\t[+] Probando parametro: $param1  \n ", RESET;  
				if ($json)
					{$new_request_parameters = "{\"$param1\":\"INJECT\"";}
				else
					{$new_request_parameters = "$param1=INJECT";}
				
				
				foreach my $hash_ref2 (@name_value_array) {					
					foreach my $param2 (keys %{$hash_ref2}) {
						if ($param1 ne $param2)
							{	
								my $current_value = ${$hash_ref2}{$param2};	
								if ($json)
									{$new_request_parameters .= ",\"$param2\":\"$current_value\"";}
								else
									{$new_request_parameters .= "&$param2=$current_value";}
							}
						}										
					}
					if ($json){$new_request_parameters .= "}";}
					
				
					open (MYINPUT,"</usr/share/webintruder/payloads/sqli.txt") || die "ERROR: Can not open the file /usr/share/webintruder/payloads/sqli.txt\n";						
					while ($inject=<MYINPUT>)
					{ 
						$inject =~ s/\n//g; 
						$final_request_parameters = $new_request_parameters; 						
						$final_request_parameters =~ s/INJECT/$inject/g; 	
						print "request_parameter2 $final_request_parameters \n" if ($debug);					
						$webintruder->request(url =>$url, method => $method, headers=> $current_headers, original_status => $original_status, original_response64 => $original_response64, test => $testType, section => $section, request_parameters => $final_request_parameters,req_id => $req_id);
						$req_id++;						
						
						}
						close MYINPUT;								
					}										 
				}
				undef @name_value_array;
				#####################################		  
		} # end sqli
		
	
	################ lfi 	#######################      
	if ($testType eq "lfi")
	{		    
		if ($method eq "GET" && $request_parameters eq "") # la variable esta al finalizar la $url https://dominio.com.bo/Usuarios/Usuario/12
		{
			# https://dominio.com.bo/Usuarios/Usuario/12	---> https://dominio.com.bo/Usuarios/Usuario/INJECT
			my $url_inject = "";
			my @url_array = split('/',$url);
			$len = $#url_array;

			for (my $i=0;$i<=$len; $i++)
			{
				if ($i ne $len)
					{$url_inject .= @url_array[$i]."/";}
				else
					{$url_inject .= "INJECT";}
			}
				
			######### send 	request https://dominio.com.bo/Usuarios/Usuario/'INJECT
			open (MYINPUT,"</usr/share/webintruder/payloads/lfi$os.txt") || die "ERROR: Can not open the file /usr/share/webintruder/payloads/lfi$os.txt\n";
			while ($inject=<MYINPUT>)
			{ 
				$inject =~ s/\n//g; 
				$final_url = $url_inject; 
				$final_url =~ s/INJECT/$inject/g; 					
				
				##post
				$final_request_parameters = $new_request_parameters; 
				#print "request_parameter2  $final_request_parameters \n" if ($debug);
				$final_request_parameters =~ s/INJECT/$inject/g; 						
				######
						
				print "final_url $final_url \n" if ($debug);
				$webintruder->request(url => $final_url, method => $method, headers=> $current_headers, original_status => $original_status, original_response64 => $original_response64, test => $testType, section => $section, request_parameters => $final_request_parameters,req_id => $req_id);
				$req_id++;														
						
			}
			close MYINPUT;
				#################################################
		}#end GET
		   			  
	    
		#POST	
		########## send error in all parameters ###############
		#print Dumper @name_value_array;
		foreach my $hash_ref (@name_value_array) {					
			foreach my $param1 (keys %{$hash_ref}) {														
				print BLUE,"\t[+] Probando parametro: $param1  \n ", RESET;  
				if ($json)
					{$new_request_parameters = "{\"$param1\":\"INJECT\"";}
				else
					{$new_request_parameters = "$param1=INJECT";}
				
				
				foreach my $hash_ref2 (@name_value_array) {					
					foreach my $param2 (keys %{$hash_ref2}) {
						if ($param1 ne $param2)
							{	
								my $current_value = ${$hash_ref2}{$param2};	
								if ($json)
									{$new_request_parameters .= ",\"$param2\":\"$current_value\"";}
								else
									{$new_request_parameters .= "&$param2=$current_value";}
							}
						}										
					}
					if ($json){$new_request_parameters .= "}";}
					
				
					open (MYINPUT,"</usr/share/webintruder/payloads/lfi$os.txt") || die "ERROR: Can not open the file /usr/share/webintruder/payloads/lfi$os.txt\n";						
					while ($inject=<MYINPUT>)
					{ 
						$inject =~ s/\n//g; 
						$final_request_parameters = $new_request_parameters; 
						#print "request_parameter2  $final_request_parameters \n" if ($debug);
						$final_request_parameters =~ s/INJECT/$inject/g; 						
						$webintruder->request(url =>$url, method => $method, headers=> $current_headers, original_status => $original_status, original_response64 => $original_response64, test => $testType, section => $section, request_parameters => $final_request_parameters,req_id => $req_id);
						$req_id++;						
						
						}
						close MYINPUT;								
					}										 
				}
				undef @name_value_array;
				#####################################		  
		} # end lfi
		
	############### error ###############	
	if ($testType eq "error")
	   {
		   			  
			#User-Agent: () { :; }; printf 'Content-Type: text/json\r\n\r\n%s vulnerable %s' 'VEGA123' 'VEGA123'
			#Referer: () { :; }; printf 'Content-Type: text/json\r\n\r\n%s vulnerable %s' 'VEGA123' 'VEGA123'
			#Accept-Language: () { :; }; printf 'Content-Type: text/json\r\n\r\n%s vulnerable %s' 'VEGA123' 'VEGA123'
			#Cookie: () { :; }; printf 'Content-Type: text/json\r\n\r\n%s vulnerable %s' 'VEGA123' 'VEGA123'
			
			######## Send request  variable[]=fsfs
			#print Dumper @name_value_array;
			my $new_request_parameters ;
			
			
			if (!($json))			
			{
				foreach my $hash_ref (@name_value_array) {					
					foreach my $param1 (keys %{$hash_ref}) {												
						print BLUE,"\t[+] Probando con el fomato $param1\[]=value \n ", RESET;  
						$new_request_parameters .= "$param1\[\]=${$hash_ref}{$param1}&";	
					}									
				}
				
				print "request_parameters $new_request_parameters \n" if ($debug);	
				$webintruder->request(url =>$url, method => $method, headers=> $current_headers, original_status => $original_status, original_response64 => $original_response64, test => $testType, section => $section, request_parameters => $new_request_parameters,req_id => $req_id, cookie => $cookie);
				$req_id++;				
				
			}			
		 ########################
		 
		 ######### la variable esta al finalizar la $url https://dominio.com.bo/Usuarios/Usuario/12
		if ($method eq "GET" && $request_parameters eq "") 
		{				
			# https://dominio.com.bo/Usuarios/Usuario/12	---> https://dominio.com.bo/Usuarios/Usuario/INJECT
			my $url_inject = "";
			my @url_array = split('/',$url);
			$len = $#url_array;

			for (my $i=0;$i<=$len; $i++)
			{
				if ($i ne $len)
					{$url_inject .= @url_array[$i]."/";}
				else
					{$url_inject .= "INJECT";}
			}
			######
			
			######### send 	request https://dominio.com.bo/Usuarios/Usuario/'INJECT
			open (MYINPUT,"</usr/share/webintruder/payloads/error.txt") || die "ERROR: Can not open the file /usr/share/webintruder/payloads/sqli.txt\n";						
			while ($inject=<MYINPUT>)
			{ 
				$inject =~ s/\n//g; 
				$final_url = $url_inject; 
				$final_url =~ s/INJECT/$inject/g; 					
				print "final_url $final_url \n" if ($debug);
			    $webintruder->request(url => $final_url, method => $method, headers=> $current_headers, original_status => $original_status, original_response64 => $original_response64, test => $testType, section => $section, request_parameters => $final_request_parameters,req_id => $req_id);
				$req_id++;																			
			}
			close MYINPUT;
			#################################################
		 }
		 #########################################################
		 
		 
		 #POST
		 ########## send Injection in all parameters ###############			   
		 foreach my $hash_ref (@name_value_array) {					
			foreach my $param1 (keys %{$hash_ref}) {													
				print BLUE,"\t[+] Probando parametro: $param1  \n ", RESET;  
				if ($json)
					{$new_request_parameters = "{\"$param1\":\"INJECT\"";}
				else
					{$new_request_parameters = "$param1=INJECT";}
					 								
				foreach my $hash_ref2 (@name_value_array) {					
					foreach my $param2 (keys %{$hash_ref2}) {
						if ($param1 ne $param2)
						{	
							my $current_value = ${$hash_ref2}{$param2};							
							if ($json)
								{$new_request_parameters .= ",\"$param2\":\"$current_value\"";}
							else
								{$new_request_parameters .= "&$param2=$current_value";}								 
						}
					}										
				}
		
				if ($json){$new_request_parameters .= "}";}
				
				open (MYINPUT,"</usr/share/webintruder/payloads/error.txt") || die "ERROR: Can not open the file /usr/share/webintruder/payloads/sqli.txt\n";						
				while ($inject=<MYINPUT>)
					{ 
					$inject =~ s/\n//g; 
					$final_request_parameters = $new_request_parameters; 
					$final_request_parameters =~ s/INJECT/$inject/g; 
					print "request_parameters $final_request_parameters \n" if ($debug);
					$webintruder->request(url =>$url, method => $method, headers=> $current_headers, original_status => $original_status, original_response64 => $original_response64, test => $testType, section => $section, request_parameters => $final_request_parameters,req_id => $req_id);
					$req_id++;												
					}
					close MYINPUT;								
				}										 
			}
			undef @name_value_array;
			#####################################		 		  
		} # error type
		
		################ ################################### #####################			    	 
	open (SALIDA,">>$section-$testType.csv") || die "ERROR: No puedo abrir el fichero $testType.csv\n";
	print SALIDA "\n\n";
	close (SALIDA);	
} #for request

