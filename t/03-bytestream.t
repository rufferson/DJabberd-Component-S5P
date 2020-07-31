#!/usr/bin/perl
use strict;
use Test::More tests => 11;

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
my $error;
my $is_error = sub {
    my ($vh,$cb,$iq) =@_;
    $DJabberd::Component::S5P::logger->debug($iq->as_xml);
    ok($iq->type eq 'error', 'Has error');
    like($iq->innards_as_xml,qr/<$error\W/, "And is $error");
    return $cb->delivered;
};
$vhost->register_hook('deliver', sub {
	return $deliver->(@_);
    });

my $query = DJabberd::XMLElement->new('http://jabber.org/protocol/bytestreams','query',{xmlns=>'http://jabber.org/protocol/bytestreams'},[]);
my $iq = DJabberd::IQ->new('jabber:client', 'iq', {
	'{}id' => 'iq1',
	'{}type' => 'set',
	'{}to' => "s5p.$domain",
	'{}from' => $partyb,
    }, [
	$query
    ]);

# Play stupid - Sanity check should err
$deliver = $is_error;
$error = 'bad-request';
$iq->deliver($vhost);

# Make it proper - Policy check should err
$query->set_attr('{}sid' => 'sid1');
my $activate = DJabberd::XMLElement->new(undef,'activate',{},[$partya]);
$query->push_child($activate);
$error = 'forbidden';
$iq->deliver($vhost);

# Swap sides - Connection check should err
$activate->remove_child($partya);
$activate->push_child($partyb);
$iq->set_from($partya);
$error = 'not-authorized';
$iq->deliver($vhost);

# Make a single connection - Proxy check should err
sub make_leg {
    my $sock;

    socket($sock, PF_INET6, SOCK_STREAM, IPPROTO_TCP) || die('socket: '.$!);
    ok(connect($sock, Socket::sockaddr_in6(51080, Socket::IN6ADDR_LOOPBACK)), 'Leg Connected');

    my $s5c = DJabberd::Connection::S5S->new($sock);
    my $hash = Digest::SHA::sha1_hex("sid1$partya$partyb");
    $s5c->start($hash);

    IO::Handle::blocking($sock, 0);
    my $steps = 9;
    Danga::Socket->SetPostLoopCallback(sub {$steps--});
    Danga::Socket->EventLoop;
    return $s5c;
}
my $s5a = make_leg($partya);
$error = 'not-allowed';
$iq->deliver($vhost);

my $s5b = make_leg($partyb);

$deliver = sub {
    my ($vh,$cb,$iq) =@_;
    $DJabberd::Component::S5P::logger->debug($iq->as_xml);
    ok($iq->type eq 'result', 'Is result');
    return $cb->delivered;
};
$iq->deliver($vhost);
