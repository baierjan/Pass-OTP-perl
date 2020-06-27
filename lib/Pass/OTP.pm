package Pass::OTP;

use utf8;
use strict;
use warnings;

use Convert::Base32 qw(decode_base32);
use Digest::HMAC;
use Digest::SHA;
use Math::BigInt;

require Exporter;
our @ISA       = qw(Exporter);
our @EXPORT_OK = qw(otp hotp totp);

=head2 hotp

    HOTP(K,C) = Truncate(HMAC-SHA-1(K,C))

    Step 1: Generate an HMAC-SHA-1 value
        Let HS = HMAC-SHA-1(K,C)

    Step 2: Generate a 4-byte string (Dynamic Truncation)
        Let Sbits = DT(HS)

    Step 3: Compute an HOTP value
        Let Snum = StToNum(Sbits)       # Convert S to a number in 0..2^{31}-1
        Return D = Snum mod 10^Digit    # D us a number in the range 0..10^{Digit}-1

    sub hotp {
        my $offset = hmac_result[19] & 0xf;
        my $bin_code = (hmac_result[offset] & 0x7f) << 24
            | (hmac_result[offset+1] & 0xff) << 16
            | (hmac_result[offset+2] & 0xff) <<  8
            | (hmac_result[offset+3] & 0xff);
    }

=cut

sub hotp {
    my %options = (
        algorithm => 'sha1',
        counter   => 0,
        digits    => 6,
        @_,
    );

    my $C = Math::BigInt->new($options{counter});

    my ($hex) = $C->as_hex =~ /^0x(.*)/;
    $hex = "0" x (16 - length($hex)) . $hex;

    my $digest = Digest::SHA->new($options{algorithm} =~ /sha(\d+)/);
    my $hmac   = Digest::HMAC->new(
        $options{base32} ? decode_base32($options{secret} =~ s/ //gr) : pack('H*', $options{secret}),
        $digest,
    );
    $hmac->add(pack 'H*', $hex);
    my $hash = $hmac->digest;

    my $offset = hex(substr(unpack('H*', $hash), -1));
    my $bin_code = unpack('N', substr($hash, $offset, 4));
    $bin_code &= 0x7fffffff;
    $bin_code = Math::BigInt->new($bin_code);

    if (defined $options{chars}) {
        my $otp = "";
        foreach (1 .. $options{digits}) {
            $otp .= substr($options{chars}, $bin_code->copy->bmod(length($options{chars})), 1);
            $bin_code = $bin_code->btdiv(length($options{chars}));
        }
        return $otp;
    }
    else {
        my $otp = $bin_code->bmod(10**$options{digits});
        return "0" x ($options{digits} - length($otp)) . $otp;
    }
}

=head2 totp

    TOTP = HOTP(K,T)
    T = (Current Unix time - T0) / X

=cut

sub totp {
    my %options = (
        'start-time' => 0,
        now          => time,
        period       => 30,
        @_,
    );

    $options{counter} = Math::BigInt->new(int(($options{now} - $options{'start-time'}) / $options{period}));
    return hotp(%options);
}

=head2 otp

    Convenience wrapper which calls totp/hotp according to options

=cut

sub otp {
    my %options = (
        type => 'hotp',
        @_,
    );

    return hotp(%options) if $options{type} eq 'hotp';
    return totp(%options) if $options{type} eq 'totp';
}

1;
