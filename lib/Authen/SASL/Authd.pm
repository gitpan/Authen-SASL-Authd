package Authen::SASL::Authd;

use strict;
use warnings;
use IO::Socket::UNIX;
use IO::Select;
use MIME::Base64 qw(encode_base64);

our($VERSION, @EXPORT, @EXPORT_OK, @ISA);

require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = qw(auth_cyrus auth_dovecot);

$VERSION = "0.01";


sub auth_cyrus {

    my ($login, $passwd, %prop) = @_;

    my $service = $prop{service_name} || '';
    my $timeout = $prop{timeout} || 5;
    my $sock_file = $prop{sock_file} || '/var/run/saslauthd/mux';
    
    my $sock = new IO::Socket::UNIX(Type => SOCK_STREAM, Peer => $sock_file) or
        die "Can't open socket. Check saslauthd is running and $sock_file readable.";

    $sock->send(pack 'n/a*n/a*n/a*xx', $login, $passwd, $service) or
        die "Can't write to $sock_file";

    my $sel = new IO::Select($sock);
    $sel->can_read($timeout) or die "Timed out while waiting for response";

    recv($sock, my $res, 4, 0);
    $sock->close;

    (unpack('na2', $res))[1] eq 'OK';
}


sub auth_dovecot {

    my ($login, $passwd, %prop) = @_;

    my $service = $prop{service_name} || '';
    my $timeout = $prop{timeout} || 5;
    my $sock_file = $prop{sock_file} || '/var/run/dovecot/auth-client';

    my $sock = new IO::Socket::UNIX(Type => SOCK_STREAM, Peer => $sock_file) or
        die "Can't open socket. Check dovecot is running and $sock_file readable.";

    my $sel = new IO::Select($sock);
    $sel->can_read($timeout) or die "Timed out while waiting for response";

    recv($sock, my $handshake, 512, 0);

    die "Unsupported protocol version"
        unless $handshake =~ /^VERSION\t1\t\d+$/m;

    die "PLAIN mechanism is not supported by the authentication daemon"
        unless $handshake =~ /^MECH\tPLAIN/m;

    my $base64 = encode_base64("\0$login\0$passwd");
    $sock->send("VERSION\t1\t0\nCPID\t$$\nAUTH\t1\tPLAIN\tservice=$service\tresp=$base64") or
        die "Can't write to $sock_file";

    $sel->can_read($timeout) or die "Timed out while waiting for response";

    recv($sock, my $result, 128, 0);
    $sock->close;

    $result =~ /^OK/;
}

1;
__END__

=head1 NAME

Authen::SASL::Authd - Client authentication via Cyrus saslauthd or
Dovecot authentication daemon.

=head1 SYNOPSIS

    use Authen::SASL::Authd qw(auth_cyrus auth_dovecot);

    print "saslauthd said ok\n" if auth_cyrus('login', 'passwd');

    print "dovecot-auth denied login\n" unless auth_dovecot('login', 'passwd');

=head1 DESCRIPTION

The C<Authen::SASL::Authd> package implements PLAIN authentication protocols
used by Cyrus saslauthd and Dovecot authentication daemon.
It can be used to process authentication requests against configured SASL mechanism
implemented by Cyrus or Dovecot SASL libraries.

=head1 METHODS

=item auth_cyrus( 'LOGIN', 'PASSWD', [ service_name => 'SERVICE_NAME', ]
    [ timeout => 'TIMEOUT (sec)', ] [ sock_file => '/SOCK/FILE/NAME', ] )

Check provided user name and password against Cyrus saslauthd.
Return true if authentication succeeded.

=item auth_dovecot( 'LOGIN', 'PASSWD', [ service_name => 'SERVICE_NAME', ]
    [ timeout => 'TIMEOUT (sec)', ] [ sock_file => '/SOCK/FILE/NAME', ] )

Check provided user name and password against Dovecot authentication daemon.
Return true if authentication succeeded.

=head1 AUTHOR

Alex Protasenko <aprotasenko@bkmks.com>

=head1 COPYRIGHT and LICENSE

Copyright 2007 by Alex Protasenko.

This program is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut

