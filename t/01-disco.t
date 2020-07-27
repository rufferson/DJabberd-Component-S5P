#!/usr/bin/perl
use strict;
use Test::More tests => 3;

use DJabberd;
DJabberd::Log::set_logger("main");
use DJabberd::VHost;
use DJabberd::Component::S5P;

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

ok($vhost->child_services->{'s5p.'.$domain} eq 'S55 Proxy', 'Has service');

my $iq = DJabberd::IQ->new('jabber:client', 'iq', {
	'{}id' => 'disco1',
	'{}type' => 'get',
	'{}to' => "s5p.$domain",
	'{}from' => "u5p\@$domain"
    }, [
	DJabberd::XMLElement->new('http://jabber.org/protocol/disco#info','query',{xmlns=>'http://jabber.org/protocol/disco#info'},[])
    ]);

$vhost->register_hook('deliver', sub {
	my ($cb,$vh,$iq) =@_;
	like($iq->innards_as_xml,qr/category=['"]proxy['"]/, 'Has category');
	like($iq->innards_as_xml,qr{var=['"]http://jabber.org/protocol/bytestreams["']}, 'Has bytestream');
    });
$iq->deliver($vhost);
