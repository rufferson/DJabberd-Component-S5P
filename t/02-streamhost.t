#!/usr/bin/perl
use strict;
use Test::More tests => 4;

use DJabberd;
DJabberd::Log::set_logger("main");
use DJabberd::VHost;
use DJabberd::Component::S5P;

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
$vhost->set_server($djabberd);

$vhost->set_config_childservice('s5p.'.$domain.' S55 Proxy');
my $s5p = DJabberd::Component::S5P->new();
$s5p->set_config_port(51080);
$s5p->set_config_host('s5p');
$s5p->finalize;
$vhost->add_plugin($s5p);

my ($partya,$partyb) = ('me@'.$domain.'/local', 'he@'.$dother.'/remote');

my $deliver;
my $forbidden = sub {
    my ($vh,$cb,$iq) =@_;
    ok($iq->type eq 'error', 'Has error');
    like($iq->innards_as_xml,qr/<forbidden\W/,'And is forbidden');
    return $cb->delivered;
};
$vhost->register_hook('deliver', sub {
	return $deliver->(@_);
    });

my $iq = DJabberd::IQ->new('jabber:client', 'iq', {
	'{}id' => 'iq1',
	'{}type' => 'get',
	'{}to' => "s5p.$domain",
	'{}from' => $partyb,
    }, [
	DJabberd::XMLElement->new('http://jabber.org/protocol/bytestreams','query',{xmlns=>'http://jabber.org/protocol/bytestreams'},[])
    ]);

$deliver = $forbidden;
$iq->deliver($vhost);

$iq->set_from($partya);
$deliver = sub {
    my ($vh,$cb,$iq) =@_;
    $DJabberd::Component::S5P::logger->debug($iq->as_xml);
    ok($iq->type eq 'result', 'Is result');
    like($iq->innards_as_xml,qr{<streamhost\s+.*jid=["']s5p\.},'And has streamhost');
    return $cb->delivered;
};
$iq->deliver($vhost);
