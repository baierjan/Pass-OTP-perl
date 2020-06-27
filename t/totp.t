use Test::More;

use utf8;
use strict;
use warnings;

use open qw(:std :utf8);
require_ok 'Pass::OTP';

sub t {
    my $cmd    = shift;
    my $secret = shift;
    my %args   = (
        'time-step-size' => '30',
        'start-time'     => 0,
        digest           => 'sha1',
        digits           => 6,
        now              => time,
        @_,
    );

    my $ret = qx($cmd);
    chomp($ret);
    my $code = ($cmd =~ /--totp/) ? Pass::OTP::totp($secret, %args) : Pass::OTP::hotp($secret, %args);
    return is($code, $ret, $cmd);
}

t(
    'oathtool 00',
    "00",
);

TODO: {
    local $TODO = "Parameter --window not implemented";
    t(
        'oathtool -w 10 3132333435363738393031323334353637383930',
        "3132333435363738393031323334353637383930",
        window => 10,
    );

    t(
        'oathtool --base32 -w 3 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        base32 => 1,
        window => 3,
    );
}

t(
    'oathtool --base32 --totp "gr6d 5br7 25s6 vnck v4vl hlao re"',
    "gr6d 5br7 25s6 vnck v4vl hlao re",
    base32 => 1,
    totp   => '',
);

t(
    'oathtool -c 5 3132333435363738393031323334353637383930',
    "3132333435363738393031323334353637383930",
    counter => 5,
);

t(
    'oathtool -b --totp --now "2008-04-23 17:42:17 UTC" IFAUCQIK',
    "IFAUCQIK",
    base32 => 1,
    totp   => '',
    now    => `date -d'2008-04-23 17:42:17 UTC' +%s`,
);

t(
    'oathtool --totp --now "2008-04-23 17:42:17 UTC" 00',
    "00",
    totp => '',
    now  => `date -d'2008-04-23 17:42:17 UTC' +%s`,
);

t(
    'oathtool --totp 00',
    "00",
    totp => '',
);

t(
'oathtool --totp --digits=8 --now "2009-02-13 23:31:30 UTC" 3132333435363738393031323334353637383930313233343536373839303132',
    "3132333435363738393031323334353637383930313233343536373839303132",
    totp   => '',
    digits => 8,
    now    => `date -d'2009-02-13 23:31:30 UTC' +%s`
);

t(
'oathtool --totp=sha256 --digits=8 --now "2009-02-13 23:31:30 UTC" 3132333435363738393031323334353637383930313233343536373839303132',
    "3132333435363738393031323334353637383930313233343536373839303132",
    totp   => 'sha256',
    digest => 'sha256',
    digits => 8,
    now    => `date -d'2009-02-13 23:31:30 UTC' +%s`,
);

TODO: {
    local $TODO = "Parameter --window not implemented";
    t(
        'oathtool --totp 00 -w5',
        "00",
        totp   => '',
        window => 5,
    );
}

TODO: {
    local $TODO = "Parameter --verbose not implemented";
    t(
        'oathtool --totp -v -N "2033-05-18 03:33:20 UTC" -d8 3132333435363738393031323334353637383930',
        "3132333435363738393031323334353637383930",
        totp    => '',
        verbose => 1,
        now     => `date -d'2033-05-18 03:33:20 UTC' +%s`,
        digits  => 8,
    );
}

done_testing(13);
