use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'webintruder',
    AUTHOR           => q{Daniel Torres <daniel.torres0085@gmail.com>},
    VERSION_FROM     => 'lib/webintruder.pm',
    ABSTRACT_FROM    => 'lib/webintruder.pm',
    LICENSE          => 'artistic_2',
    PL_FILES         => {},
    MIN_PERL_VERSION => 5.006,
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => 0,
    },
    BUILD_REQUIRES => {
        'Test::More' => 0,
        
    },
      PREREQ_PM => {
        'Moose' => 0,
        'Net::SSL' => 0,
        'LWP::UserAgent' => 0,
        'Text::Table' => 0,
        'URI::Escape' => 0,
        'HTTP::Cookies' => 0,
        'HTTP::Request' => 0,
        'HTTP::Response' => 0,
        'Getopt::Std' => 0,         
        'Term::ANSIColor' => 0, 
        'MIME::Base64 ' =>0,
        'XML::Simple' =>0,
        'JSON' =>0,
        
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'webintruder-*' },
);
