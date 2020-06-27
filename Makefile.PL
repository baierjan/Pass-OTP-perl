use strict;
use warnings;

use ExtUtils::MakeMaker;

WriteMakefile(
    NAME           => 'Pass::OTP',
    AUTHOR         => q{Jan Baier <jan.baier@amagical.net>},
    ABSTRACT_FROM  => 'lib/Pass/OTP.pm',
    VERSION_FROM   => 'bin/oathtool',
    LICENSE        => 'perl_5',
    EXE_FILES      => ['bin/oathtool'],
    TEST_REQUIRES => {
        'Test::More' => '0',
    },
    PREREQ_PM => {
        'Convert::Base32' => '0',
        'Digest::HMAC' => '0',
        'Digest::SHA' => '0',
        'Math::BigInt' => '0',
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Pass-OTP-*' },
);
