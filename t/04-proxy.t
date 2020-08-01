#!/usr/bin/perl
use strict;
use Test::More tests => 7;

use Socket qw(PF_INET PF_INET6 IPPROTO_TCP SOCK_STREAM AF_INET AF_INET6);
use DJabberd;
DJabberd::Log::set_logger("main");
use DJabberd::VHost;
use DJabberd::Component::S5P;
use DJabberd::Connection::S5S;

sub run_before { 'DJabberd::Delivery::S2S'}
sub run_after { 'DJabberd::Delivery::Local'}

my $domain = "example.com";
my $dother = "example.org";

my $plugs = [
            DJabberd::Delivery::Local->new,
            DJabberd::Delivery::S2S->new
	];
my $vhost = DJabberd::VHost->new(
            server_name => $domain,
            s2s         => 1,
            plugins     => $plugs,
        );

my $djabberd = DJabberd->new;
$djabberd->add_vhost($vhost);

$vhost->set_config_childservice('s5p.'.$domain.' S55 Proxy');
my $s5p = DJabberd::Component::S5P->new();
$s5p->set_config_port(51080);
$s5p->set_config_host('s5p');
$s5p->finalize;
$vhost->add_plugin($s5p);

my ($partya,$partyb) = ('me@'.$domain.'/local', 'he@'.$dother.'/remote');

my $deliver;
$vhost->register_hook('deliver', sub {
	return $deliver->(@_);
    });

my $activate = DJabberd::XMLElement->new(undef,'activate',{},[$partyb]);
my $query = DJabberd::XMLElement->new('http://jabber.org/protocol/bytestreams','query',{
	xmlns=>'http://jabber.org/protocol/bytestreams',
	'{}sid' => 'sid1',
    },[
	$activate,
    ]);
my $iq = DJabberd::IQ->new('jabber:client', 'iq', {
	'{}id' => 'iq1',
	'{}type' => 'set',
	'{}to' => "s5p.$domain",
	'{}from' => $partya,
    }, [
	$query,
    ]);

my $steps = 0;
Danga::Socket->SetPostLoopCallback(sub {$steps--});

sub make_leg {
    my $sock;

    socket($sock, PF_INET6, SOCK_STREAM, IPPROTO_TCP) || die('socket: '.$!);
    ok(connect($sock, Socket::sockaddr_in6(51080, Socket::IN6ADDR_LOOPBACK)), 'Leg Connected');

    my $s5c = Test::S5C->new($sock);
    my $hash = Digest::SHA::sha1_hex("sid1$partya$partyb");
    $s5c->start($hash);

    IO::Handle::blocking($sock, 0);
    $steps = 9;
    Danga::Socket->EventLoop;
    return $s5c;
}
my $s5a = make_leg();
my $s5b = make_leg();

$deliver = sub {
    my ($vh,$cb,$iq) =@_;
    $DJabberd::Component::S5P::logger->debug($iq->as_xml);
    ok($iq->type eq 'result', 'Is result');
    return $cb->delivered;
};
$iq->deliver($vhost);

my $test = sub {
    ok($_[0]->{buf} eq $_[1], 'Has the data');
};

$s5b->{buf} = "Blah!";
$s5a->write($s5b->{buf});
$steps = 3;

Danga::Socket->EventLoop;

$s5a->{buf} = "That was easy";
$s5b->write($s5a->{buf});
$steps = 3;

Danga::Socket->EventLoop;

my $s5c = make_leg();
ok($s5c->{closed} && $s5c->{state} == DJabberd::Connection::S5S::CLOSED, 'Was closed inflight');

##
# Client S5 connection
package Test::S5C;
use base 'DJabberd::Connection::S5S';

sub event_read {
    my ($self) = @_;
    if($self->{state} == DJabberd::Connection::S5S::CONNECT) {
	my $bfr = $self->read(40_000);
	return $self->close unless(defined $bfr);
	$self->log("Read: $bfr; Data: ".$$bfr);
	$test->($self, $$bfr);
    } else {
	$self->SUPER::event_read(@_);
    }
}
