#!/usr/bin/perl
# Tiny TCP forwarder: 127.0.0.1:<listen> -> <host>:<port>.
#
# Used on Apple silicon to put Tart VMs' SSH on a fixed loopback port (2230 Linux,
# 2231 macOS), matching the ports Vagrant forwards on Intel, so the collector
# container reaches every VM the same way (host.docker.internal:<port>).
#
#     forward.pl 2231 192.168.64.5 22
#
# Perl, not Python: every macOS Python (Homebrew's, Xcode's) runs as an app bundle
# (Python.app) that needs its own Local Network permission to reach a VM's 192.168.64.x
# address, and started in the background it is refused without ever being asked
# ("No route to host"). /usr/bin/perl is a plain binary and runs under the terminal's.
use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;

my ($listen, $host, $port) = @ARGV;
die "usage: forward.pl <listen> <host> <port>\n" unless defined $port;
$SIG{CHLD} = 'IGNORE';
$| = 1;

my $server = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1', LocalPort => $listen, Listen => 16, ReuseAddr => 1,
) or die "can't listen on 127.0.0.1:$listen: $!\n";

while (1) {
    my $client = $server->accept or next;
    my $pid = fork;
    if (!defined $pid) { close $client; next; }
    if ($pid) { close $client; next; }
    close $server;
    my $upstream = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port, Timeout => 10);
    if (!$upstream) {
        # Said, not swallowed: "No route to host" here is macOS's Local Network permission
        print STDERR "can't reach $host:$port: $!\n";
        exit 1;
    }
    my %peer = ($client => $upstream, $upstream => $client);
    my $select = IO::Select->new($client, $upstream);
    RELAY: while (my @ready = $select->can_read) {
        for my $from (@ready) {
            my $n = sysread($from, my $buf, 65536);
            last RELAY unless $n;
            my $to = $peer{$from};
            my $off = 0;
            while ($off < $n) {
                my $w = syswrite($to, $buf, $n - $off, $off);
                last RELAY unless $w;
                $off += $w;
            }
        }
    }
    exit 0;
}
