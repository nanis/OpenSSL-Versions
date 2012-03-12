 #!perl -T

use strict; use warnings;
use Test::More;

use OpenSSL::Versions qw( parse_openssl_version_number );

my @cases = (
    [ '0x0090812f' => '0.9.8r' ],
    [ '0x0090704f' => '0.9.7d' ],
    [ '0x009060af' => '0.9.6j' ],
    [ '0x0090805f' => '0.9.8e' ],
    [ '0x1000007f' => '1.0.0g' ],
    [ '0x102031af' => '1.2.3z' ],
);

for my $case ( @cases ) {
    my ($input, $expected) = @$case;
    is(
        parse_openssl_version_number($input),
        $expected,
        "$input => $expected",
    );
}

done_testing;

