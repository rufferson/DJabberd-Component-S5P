package DJabberd::Component::S5P;
use base DJabberd::Component;
use warnings;
use strict;

use constant NS_BYTESTREAMS => 'http://jabber.org/protocol/bytestreams';
use constant NSERR => 'urn:ietf:params:xml:ns:xmpp-stanzas';

our $logger = DJabberd::Log->get_logger();

=head1 NAME

DJabberd::Component::S5P - Implements XEP-0065 Socks5 Proxy

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

sub run_after  { qw(DJabberd::Delivery::Local) }
sub run_before { qw(DJabberd::Delivery::S2S) }

=head1 SYNOPSIS

Implements XEP-0065 Bytestreams SOCKS5 Proxy.

    <VHost mydomain.com>
	<Plugin DJabberd::Component::S5P>
	    Host proxy
	    Port 5280
	    ExtIP ""
	</Plugin>
    </VHost>

This will create component with default settings so the same could be done by

    <VHost mydomain.com>
	<Plugin DJabberd::Component::S5P />
    </VHost>

and this will also respond with
    
    <streamhost host="proxy.domain.com" jid="proxy.domain.com" port="5280"/>

to bytestream query.

=over

=item Host

A hostname prefix to be used for a compnent. Prepended to the VHost's domain.

=item Port

A port (including optional address) to bind to for incoming connections.

=item ExtIP

Optional External IP parameter to override host in bytestream network address
query with different value - value is taken verbatim, could be IP or FQDN.

=back

=cut


sub set_config_host {
    my ($self,$host) = @_;
    $self->{host} = $host;
}

sub set_config_port {
    my ($self, $port) = @_;
    $self->{port} = DJabberd::Util::as_bind_addr($port);
}

sub set_config_extip {
    my ($self, $ext) = @_;
    $self->{extip} = $ext;
}

sub discover {
    my ($self, $iq) =@_;
    $logger->debug("Discovering streamhost from ".$iq->from);
    unless($self->vhost->handles_jid($iq->from_jid)) {
	my $err = $self->erply($iq, 'auth', 'forbidden');
	$err->deliver($self->vhost);
	return;
    }
    unless($self->{proxy}) {
	my $err = $self->erply($iq, 'cancel', 'not-allowed');
	$err->deliver($self->vhost);
	return;
    }
    my $query = $iq->first_element->clone;
    my $jid = $self->domain;
    my $host = $self->{exthost} || $self->domain;
    my $port = $self->{port};
    my $rsp = $iq->make_response;
    $query->set_raw("<streamhost host='$host' jid='$jid' port='$port'/>");
    $rsp->set_raw($query->as_xml);
    $rsp->deliver($self->vhost);
}

sub activate {
    my ($self, $iq) =@_;
    my ($rsp,$err,$err_el,$err_msg,$hash);
    my $qry = $iq->first_element;
    if($qry && $qry->attr('{}sid') && $qry->first_element) {
	my $sid = $qry->attr('{}sid');
	my $tgt = $qry->first_element->innards_as_xml;
	my $from = $iq->from;
	$hash = Digest::SHA::sha1_hex("$sid$from$tgt");
    }
    if(!$hash) {
	$err = 'modify';
	$err_el = 'bad-request';
	$err_msg = 'Me no understand';
    } elsif(!$self->vhost->handles_jid($iq->from_jid)) {
	$err = 'auth';
	$err_el = 'forbidden';
	$err_msg = 'residents only';
    } elsif(!$self->{proxy}) {
	$err = 'cancel';
	$err_el = 'internal-server-error';
	$err_msg = 'Proxy Service has not been initialized,';
    #} elsif() {
	# Not sure how is it possible to detect this error
	# as there's no request per se, only S5 connections
	#$err = 'cancel';
	#$err_el = 'item-not-found';
	#$err_msg = "'from' does not match Requester's full JID";
    } elsif(!ref($self->{scs}->{$hash})) {
	$err = 'auth';
	$err_el = 'not-authorized';
	$err_msg = 'Hash is not matching: '.$hash;
    } elsif(scalar(@{ $self->{scs}->{$hash} }) < 2) {
	$err = 'cancel';
	$err_el = 'not-allowed';
	$err_msg = 'Not all parties are connected';
    } else {
	for my $conn (@{ $self->{scs}->{$hash} }) {
	    $conn->activate( @{ $self->{scs}->{$hash} });
	}
	$rsp = $iq->make_response;
    }
    $rsp = $self->erply($iq, $err, $err_el, $err_msg) if($err);
    $rsp->deliver($self->vhost);
}

sub add_conn {
    my ($self, $conn) = @_;
    push(@{ $self->{scs}{$conn->hash} ||= [] }, $conn);
    if(scalar(@{ $self->{scs}->{$conn->hash} }) > 2) {
	my $ex = shift(@{ $self->{scs}->{$conn->hash} });
	$ex->close();
    }
}

sub finalize {
    my ($self, $opts) = @_;
    $self->{host} ||= 'proxy';
    $self->{port} ||= 5280;
    $self->{scs} = {};
    
    $self->SUPER::finalize;

    my $get_handler = sub {
	my ($vh,$iq) = @_;
	$self->discover($iq);
    };
    my $set_handler = sub {
	my ($vh,$iq) = @_;
	$self->activate($iq);
    };
    $self->register_iq_handler('get-{'.NS_BYTESTREAMS.'}query',$get_handler);
    $self->register_iq_handler('set-{'.NS_BYTESTREAMS.'}query',$set_handler);
}

sub register {
    my ($self, $vhost) = @_;
    $vhost->register_hook("GetPlugin", sub { $_[1]->set($self) if($_[2] eq __PACKAGE__) });
    $self->{proxy} = $vhost->server->_start_server($self->{port}, 'DJabberd::Connection::S5S');
    $self->SUPER::register($vhost);
}

sub features {
    my $self = shift;
    my $ftrs = $self->SUPER::features(@_);
    push(@{$ftrs},NS_BYTESTREAMS);
    return $ftrs;
}

sub identities {
    my $self = shift;
    my $idts = $self->SUPER::identities(@_);
    push(@{$idts},['proxy','bytestreams','Bytestream Relay']);
    return $idts;
}

sub erply {
    my ($self, $iq, $err, $err_el, $err_msg) = @_;
    my $e = DJabberd::XMLElement->new('','error',
	    {type=>$err},
	    [ DJabberd::XMLElement->new(NSERR,$err_el,{xmlns=>NSERR},[]) ]
    );
    $e->push_child(DJabberd::XMLElement->new(NSERR,'text',{},[],$err_msg)) if($err_msg);
    $err = $iq->make_response;
    $err->set_attr('{}type','error');
    $err->push_child($iq->first_element);
    $err->push_child($e);
    return $err;
}

sub domain {
    my $self = shift;
    return $self->{host}.".".$self->vhost->server_name;
}

sub vcard {
    my ($self, $requester_jid) = @_;

    return "<N>".$self->domain."</N><FN>Web Services</FN>";
}

=head1 AUTHOR

Ruslan N. Marchenko, C<< <me at ruff.mobi> >>

=head1 COPYRIGHT & LICENSE

Copyright 2016 Ruslan N. Marchenko, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut
1;
