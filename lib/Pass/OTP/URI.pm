package Pass::OTP::URI;

use utf8;
use strict;
use warnings;

require Exporter;
our @ISA       = qw(Exporter);
our @EXPORT_OK = qw(parse);

sub parse {
    my ($uri) = @_;

    my %options = (
        base32 => 1,
    );
    ($options{type}, $options{label}, my $params) = $uri =~ m#^otpauth://([th]otp)/((?:[^:?]+(?::|%3A))?[^:?]+)\?(.*)#;

    foreach my $param (split(/&/, $params)) {
        my ($option, $value) = split(/=/, $param);
        $options{$option} = $value;
    }

    return (%options);
}

1;
