package OpenSSL::Versions;

use 5.006;
use strict;
use warnings;
use Carp;
use Exporter qw( import );
use Try::Tiny;

our $VERSION = '0.001';
$VERSION = eval $VERSION;

our @EXPORT = ();
our @EXPORT_OK = qw( parse_openssl_version_number );

sub parse_openssl_version_number {
    my ($hex_str) = @_;
    
    unless (defined $hex_str) {
        croak "Must be called with string value of OPENSSL_VERSION_NUMBER as first argument";
    }

    if ($hex_str !~ /^0x0/) {
        return _parse_post_v1_openssl_version_number($hex_str);
    }

    require OpenSSL::Versions::Table;
    OpenSSL::Versions::Table->import( 'lookup_openssl_version_number' );

    return lookup_openssl_version_number($hex_str);
}

sub _parse_post_v1_openssl_version_number {
    my ($hex_str) = @_;

    # from crypto/opensslv.h
    # MNNFFPPS: major minor fix patch status
    # The status nibble has one of the values 0 for development, 
    # 1 to e for betas 1 to 14, 
    # and f for release. The patch level is exactly that.

    my $xdigit = '[[:xdigit:]]';
    my $pat = join '', map "(${xdigit}{$_})", (1, 2, 2, 2, 1);

    my @parts = ($hex_str =~ /^0x$pat\z/);

    unless (@parts == 5) {
        croak "'$hex_str' does not look like a valid OpenSSL v1+ version number";
    }

    my ($major, $minor, $fix, $patch, $status) = map hex, @parts;

    $patch = $patch ? chr( ord('a') + $patch - 1 ) : '';

    if    ( $status ==  0 ) { $status = '-dev' }
    elsif ( $status == 15 ) { $status = '' }
    else                    { $status = "-beta$status" }

    return sprintf( '%u.%u.%u%s%s', $major, $minor, $fix, $patch, $status);
}

1;

__END__

=head1 NAME

OpenSSL::Versions - Parse OpenSSL version number

=head1 VERSION

Version 0.001

=head1 SYNOPSIS

Parse OpenSSL version number from source code.

    use OpenSSL::Versions qw( parse_openssl_version_number );
    my $v = parse_openssl_version_number('0x0913');
    print "$v\n";

Outputs:

    0.9.1c


=head1 MOTIVATION

OpenSSL source code uses a hexadecimal number which encodes various bits of
information. The meaning of various parts have changed over the history of the
library. For example, you have

    #define OPENSSL_VERSION_NUMBER	0x0913	/* Version 0.9.1c is 0913 */

versus

    #define OPENSSL_VERSION_NUMBER	0x1000007fL /* OpenSSL 1.0.0g */


The evolution of the version number scheme is explained in the
C<crypto/opensslv.h> file in recent distributions. If you have a system wide
default OpenSSL library, and you want to determine its version, that is as
simple as invoking a command line utility:

    $ openssl version
    OpenSSL 1.0.0g 18 Jan 2012

However, if all you have is the source code, and you want to determine exact
version information on the basis of the string representation of the
OPENSSL_VERSION_NUMBER macro, you have to use pattern matching and deal with a
bunch of corner cases. The post v.1.0.0 case is easy, but there are various
breakpoints in the release history. Any routine you write must be tested and
verified against the existing distributions.

I had inserted such a routine in the C<Makefile.PL> for L<Crypt::SSLeay>. That
routine was not formally tested. I had just thrown a bunch of version numbers
at it and tinkered with it until it seemed to produce the appropriate strings
in response.

So, I decided to write proper tests for it. To write the tests, I needed to
make a table of all values for OPENSSL_VERSION_NUMBER in the source code for
all available OpenSSL distributions and the corresponding version strings. I
fired up C<wget>, downloaded all the archives from
L<http://www.openssl.org/source/> and wrote a quick parsing script which simply
associated with the value of the macro OPENSSL_VERSION_NUMBER the name of the
C<.tar.gz> file in which it was found.

So, I was ready to write the tests, right?

Well, what was the point of hiding in a test file the information I had just
extracted? So, I decided to put together a module to distribute the
information. However, I did not want to have to update the module every time a
new version of the OpenSSL library was made available.

Given that the format seems to be much more stable starting with 1.0.0, the
C<parse_openssl_version> function provided by this module checks if the string
it was passed starts with the digit 1. If so, it simply parses the hexadecimal
string using pattern matching. Otherwise, it looks up the human-friendly
version string in a table.

=head1 EXPORT

By default, this module does not export anything. However, you can ask for
C<parse_openssl_version_number> to be exported.

=head1 SUBROUTINES

=head2 parse_openssl_version_number

Takes a hexadecimal string corresponding to the value
of the macro C<OPENSSL_VERSION_NUMBER> macro in either C<crypto.h> or
C<openssl/opensslv.h> file in an OpenSSL distribution and returns a human
friendly version string such as '0.9.8q'.

=head1 AUTHOR

A. Sinan Unur, C<< <nanis at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-openssl-versions at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=OpenSSL-Versions>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc OpenSSL::Versions


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=OpenSSL-Versions>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/OpenSSL-Versions>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/OpenSSL-Versions>

=item * Search CPAN

L<http://search.cpan.org/dist/OpenSSL-Versions/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright (c) 2012 A. Sinan Unur.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.
