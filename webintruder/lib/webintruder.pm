#module-starter --module=webintruder --author="Daniel Torres" --email=daniel.torres0085@gmail.com
# Aug 27 2012
# webintruder interface
package webintruder;
our $VERSION = '1.0';
use Moose;
use Data::Dumper;
use LWP::UserAgent;
use HTTP::Cookies;
use JSON qw( decode_json ); 
use URI::Escape;
use HTTP::Request;
use HTTP::Response;
use Net::SSL (); # From Crypt-SSLeay
use MIME::Base64 qw( decode_base64 );
no warnings;

$Net::HTTPS::SSL_SOCKET_CLASS = "Net::SSL"; # Force use of Net::SSL for proxy compatibility

{
has user_agent      => ( isa => 'Str', is => 'rw', default => '' );
has proxy_host      => ( isa => 'Str', is => 'rw', default => '' );
has proxy_port      => ( isa => 'Str', is => 'rw', default => '' );
has proxy_user      => ( isa => 'Str', is => 'rw', default => '' );
has proxy_pass      => ( isa => 'Str', is => 'rw', default => '' );
has proxy_env      => ( isa => 'Str', is => 'rw', default => '' );
has debug      => ( isa => 'Int', is => 'rw', default => 0 );
has headers  => ( isa => 'Object', is => 'rw', lazy => 1, builder => '_build_headers' );
has browser  => ( isa => 'Object', is => 'rw', lazy => 1, builder => '_build_browser' );


sub request
{
	
  my $self = shift;
  my %options = @_;
  my $method = $options{ method };
  my $section = $options{ section };
  my $original_status = $options{ original_status };
  my $original_response64 = $options{ original_response64 };
  my $test = $options{ test };
  my $url = $options{ url };
  my $req_id = $options{ req_id };
  my $headers = $options{ headers };
  my $cookie = $options{ cookie };
  my $request_parameters = $options{ request_parameters }; 
  
  my $original_response = decode_base64($original_response64);
    
  my $response;
  my $match_status;  
  my $error_response;
  my $pwned=0;


my @sqlerrors = ( 'error in your SQL syntax',
 'mysql_fetch',
 'Undefined index',
 'sqlsrv_fetch_object',
 'sqlsrv_fetch_array',
 'sqlsrv_free_stmt',
 'CDbCommand',
 "Unclosed quotation mark after the character",
 'num_rows',
 "syntax error at or near",
 "SQL command not properly ended",
 'ORA-01756',
 "quoted string not properly terminated",
 'Error Executing Database Query',
 "Failed to open SQL Connection",
 'SQLServer JDBC Driver',
 'Microsoft OLE DB Provider for SQL Server',
 'Unclosed quotation mark',
 'ODBC Microsoft Access Driver',
 'Microsoft JET Database',
 'Error Occurred While Processing Request',
 'Server Error',
 'Microsoft OLE DB Provider for ODBC Drivers error',
 'Invalid Querystring',
 'OLE DB Provider for ODBC',
 'VBScript Runtime',
 'ADODB.Field',
 'BOF or EOF',
 'ADODB.Command',
 'JET Database',
 'mysql_fetch_array()',
 'Syntax error',
 'mysql_numrows()',
 'at eval',
 'eval at',
 'A Database Error Occurred',
 'error de sintaxis en o cerca de',
 'GetArray()',
 'FetchRow()');


  if ($method eq "GET")
	{
	   my $final_url ;
	
	   if ($request_parameters ne "")
    	  {$final_url = $url."?$request_parameters";}
	   else
		  {$final_url = $url}
		
	  $response = $self->dispatch(url =>$final_url, method => 'GET',headers => $headers);
	}
  else
	{$response = $self->dispatch(url =>$url, method => $method, post_data =>$request_parameters, headers => $headers);}	
	
	my $response_header = '';
	
	eval {
		 $response_header = $response->as_string;				
		 $response_header =~ s/\n\n.*//s;	#delete everything after \n\n

	};
	if ($@){ warn $@;} 



	

	my $status = $response->status_line;
	print "status $status \n" ; 
	my $decoded_content = $response->decoded_content;
	
	my $final_content = "$response_header\n\n$decoded_content";
	my $responselength = length($final_content);	
	
	####### check if current status response code is the same
	
	if (! ($status =~ /$original_status/m))
		{$match_status = 0;}
	else
		{$match_status = 1;}	
	##################	
		
   ###### check error in response #####   
	foreach (@sqlerrors)
	{	
		 if($decoded_content =~ /$_/i)
		 {
			$error_response = $_;
			
			 if ($status =~ /200/m){	 
				 $pwned=1;
			 }			
			last;
		  }
		else
			{$error_response = ""}
	}
  
   
	#############################	
	my $value;
	if ($test eq "session")
		{$value = $cookie;}
	else	
		{$value = $request_parameters;}
	
	$value =~ s/;/~/g; 
	
	open (SALIDA,">>$section-$test.csv") || die "ERROR: No puedo abrir el fichero $test.csv\n";
	print SALIDA "$req_id;\"$url\";$method;\"$value\";$original_status;$status;$match_status;$error_response;$responselength\n";
	close (SALIDA);	
	
	
	
	open (SALIDA,">log/$test/$req_id.html") || die "ERROR: No puedo abrir el fichero log/$test/$req_id.html \n";
	print SALIDA "$final_content\n";
	close (SALIDA);

return $pwned;
}
		
###################################### internal functions ###################
sub dispatch {    
my $self = shift;
my $debug = $self->debug;
my %options = @_;

my $url = $options{ url };
my $method = $options{ method };
my $headers = $options{ headers };
my $response;
 


if ($method eq 'POST_OLD')
  {     
   my $post_data = $options{ post_data };        
   $response = $self->browser->post($url,$post_data);
  }  

if ($method eq 'PUT')
  {     
   my $post_data = $options{ post_data };           
   my $req = HTTP::Request->new(PUT => $url, $headers);
   $req->content($post_data);
   $response = $self->browser->request($req);  
  }  


if ($method eq 'PATCH')
  {     
   my $post_data = $options{ post_data };           
   my $req = HTTP::Request->new(PATCH => $url, $headers);
   $req->content($post_data);
   $response = $self->browser->request($req);  
  }  


if ($method eq 'LOCK')
  {     
   my $post_data = $options{ post_data };           
   my $req = HTTP::Request->new(LOCK => $url, $headers);
   $req->content($post_data);
   $response = $self->browser->request($req);  
  } 
         
if ($method eq 'UNLOCK')
  {     
   my $post_data = $options{ post_data };           
   my $req = HTTP::Request->new(UNLOCK => $url, $headers);
   $req->content($post_data);
   $response = $self->browser->request($req);  
  }   

if ($method eq 'LINK')
  {     
   my $post_data = $options{ post_data };           
   my $req = HTTP::Request->new(LINK => $url, $headers);
   $req->content($post_data);
   $response = $self->browser->request($req);  
  } 
         
if ($method eq 'UNLINK')
  {     
   my $post_data = $options{ post_data };           
   my $req = HTTP::Request->new(UNLINK => $url, $headers);
   $req->content($post_data);
   $response = $self->browser->request($req);  
  }               

if ($method eq 'PROFIND')
  {     
   my $post_data = $options{ post_data };           
   my $req = HTTP::Request->new(PROFIND => $url, $headers);
   $req->content($post_data);
   $response = $self->browser->request($req);  
  }        
  
if ($method eq 'COPY')
  {     
   my $post_data = $options{ post_data };           
   my $req = HTTP::Request->new(COPY => $url, $headers);
   $req->content($post_data);
   $response = $self->browser->request($req);  
  }        

if ($method eq 'HEAD')
  {     
   my $post_data = $options{ post_data };           
   my $req = HTTP::Request->new(HEAD => $url, $headers);
   $req->content($post_data);
   $response = $self->browser->request($req);  
  }        

if ($method eq 'OPTIONS')
  {     
   my $post_data = $options{ post_data };           
   my $req = HTTP::Request->new(OPTIONS => $url, $headers);
   $req->content($post_data);
   $response = $self->browser->request($req);  
  }        
        
if ($method eq 'CONNECT')
  {     
   my $post_data = $options{ post_data };           
   my $req = HTTP::Request->new(CONNECT => $url, $headers);
   $req->content($post_data);
   $response = $self->browser->request($req);  
  }        

if ($method eq 'HEAD')
  {     
   my $post_data = $options{ post_data };           
   my $req = HTTP::Request->new(HEAD => $url, $headers);
   $req->content($post_data);
   $response = $self->browser->request($req);  
  }        

if ($method eq 'VIEW')
  {     
   my $post_data = $options{ post_data };           
   my $req = HTTP::Request->new(VIEW => $url, $headers);
   $req->content($post_data);
   $response = $self->browser->request($req);  
  }        
                                        
    
if ($method eq 'GET')
  { my $req = HTTP::Request->new(GET => $url, $headers);
    $response = $self->browser->request($req)
  }
  
if ($method eq 'POST')
  {     
   my $post_data = $options{ post_data };           
   my $req = HTTP::Request->new(POST => $url, $headers);
   $req->content($post_data);
   $response = $self->browser->request($req);    
  }  

if ($method eq 'DELETE')
  {     
   my $post_data = $options{ post_data };           
   my $req = HTTP::Request->new(DELETE => $url, $headers);
   $req->content($post_data);
   $response = $self->browser->request($req);  
  }        

  
if ($method eq 'POST_MULTIPART')
  {    	   
   my $post_data = $options{ post_data }; 
   $headers->header('Content_Type' => 'multipart/form-data');
    my $req = HTTP::Request->new(POST => $url, $headers);
   $req->content($post_data);
   #$response = $self->browser->post($url,Content_Type => 'multipart/form-data', Content => $post_data, $headers);
   $response = $self->browser->request($req);    
  } 

if ($method eq 'POST_FILE')
  { 
	my $post_data = $options{ post_data };         	    
	$headers->header('Content_Type' => 'application/atom+xml');	
    my $req = HTTP::Request->new(POST => $url, $headers);
    $req->content($post_data);
    #$response = $self->browser->post( $url, Content_Type => 'application/atom+xml', Content => $post_data, $headers);                 
    $response = $self->browser->request($req);    
  }  
      
  
return $response;
}


sub remove_duplicates
{
 my $self = shift;		
my (@array) = @_; 

my %seen;
for ( my $i = 0; $i <= $#array ; )
{
    splice @array, --$i, 1
        if $seen{$array[$i++]}++;
}

return @array;
}

######
#Convert a hash in a string format used to send POST request
sub convert_hash
{
my ($hash_data)=@_;
my $post_data ='';
foreach my $key (keys %{ $hash_data }) {    
    my $value = $hash_data->{$key};
    $post_data = $post_data.uri_escape($key)."=".$value."&";    
}	
chop($post_data); # delete last character (&)
 #$post_data = uri_escape($post_data);
return $post_data;
}

################################### build objects ########################

################### build headers object #####################
sub _build_headers {   
my $self = shift;
my $debug = $self->debug;
print "building header \n" if ($debug);
my $headers = HTTP::Headers->new;
$headers->header('Content-Type' => 'application/x-www-form-urlencoded');	#algunas app requieren este header			  
#$headers->header('User-Agent' => $user_agent); 

return $headers; 
}

################### build browser object #####################	

sub _build_browser {    

my $self = shift;

my $debug = $self->debug;
my $proxy_host = $self->proxy_host;
my $proxy_port = $self->proxy_port;
my $proxy_user = $self->proxy_user;
my $proxy_pass = $self->proxy_pass;
my $proxy_env = $self->proxy_env;

print "building browser \n" if ($debug);

my $browser = LWP::UserAgent->new;

$browser->timeout(20);
$browser->show_progress(1) if ($debug);
$browser->max_redirect(0);


print "proxy_env $proxy_env \n" if ($debug);

if ( $proxy_env eq 'ENV' )
{
print "set ENV PROXY \n" if ($debug);
$Net::HTTPS::SSL_SOCKET_CLASS = "Net::SSL"; # Force use of Net::SSL
$ENV{HTTPS_PROXY} = "http://".$proxy_host.":".$proxy_port;

}
elsif (($proxy_user ne "") && ($proxy_host ne ""))
{
 $browser->proxy(['http', 'https'], 'http://'.$proxy_user.':'.$proxy_pass.'@'.$proxy_host.':'.$proxy_port); # Using a private proxy
}
elsif ($proxy_host ne "")
   { $browser->proxy(['http', 'https'], 'http://'.$proxy_host.':'.$proxy_port);} # Using a public proxy
 else
   { 
      $browser->env_proxy;} # No proxy       

return $browser;     
}
    
}
1;
