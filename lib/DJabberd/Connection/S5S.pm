package DJabberd::Connection::S5S;
use strict;
use warnings;
use base 'Danga::Socket';

use constant WAITING => 0;
use constant STARTED => 1;
use constant AUTHEN  => 2;
use constant CONNECT => 3;
use constant ACTIVE  => 4;
use constant CLOSED  => 5;

use fields qw(buf srv state hash peers);

sub new {
    my ($class, $sock, $server) = @_;
    my $self = $class->SUPER::new($sock);
    $self->{srv} = $server;
    $self->{state} = WAITING;
    return $self;
}

sub hash { $_[0]->{hash} }

sub event_read {
    my ($self) = @_;
    my $bfr = $self->read(40_000);
    return $self->close unless(defined $bfr);

    if($self->{state} < CONNECT) {
	$self->{buf} .= $$bfr;
	$self->handshake;
    } elsif($self->{state} == ACTIVE) {
	for my $peer (@{$self->{peers}}) {
	    next if $peer == $self;
	    $peer->write($$bfr);
	}
    }
}

sub handshake {
    my ($self) = @_;
    if($self->{state} == WAITING) {
	my ($ver, $mn) = unpack('CC', $self->{buf});
	return $self->err('Ver:', $ver,'Met:',$mn)
	    unless($ver == 5 && $mn > 0);
	return unless($mn > 0 && length($self->{buf}) < ($mn + 2));
	my @ms = unpack("xxC$mn",$self->{buf});
	if(grep{$_==0}@ms) {
	    $self->{state} = AUTHEN;
	    return $self->write(pack('CC',5,0));
	}
	$self->write(pack('CC',5,255));
	return $self->err('No supported auth[0]');
    } elsif($self->{state} == STARTED) {
	# Undocumented and impossible here
	die 'Should not reach here';
    } elsif($self->{state} == AUTHEN) {
	return if(length($self->{buf}) < 5);
	my ($ver, $cmd, $rsv, $at, $al) = unpack('C5', $self->{buf});
	return $self->err('Ver:',$ver,'Cmd:',$cmd,'Type:',$at,'AL:',$al)
	    unless($ver == 5 && $cmd == 1 && $at == 3 && $al == 40);
	return if(length($self->{buf}) < 47); # 5 + $al + 2
	my ($hash, $port) = unpack("xxxxx A40 S", $self->{buf});
	return $self->err('Hash:',$hash,'Port:',$port)
	    unless($hash =~ /^[a-fA-F0-9]+$/ && $port == 0);
	$self->{hash} = $hash;
	$self->write(pack('CCCCCA40S',5,0,0,3,40,$hash,0));
	$self->{state} = CONNECT;
	# Now broadcast our socket to all vhosts
	DJabberd::for_each_vhost(sub {
	    my ($vhost) = @_;
	    $vhost->hook_chain_fast('GetPlugin',
		[ 'DJabberd::Plugin::S5P' ],
		{
		    set => sub { $_[1]->add_conn($self); }
		});
	});
    }
}

sub activate {
    my ($self, @peers) = @_;
    $self->{buf} = undef;
    $self->{peers} = \@peers;
    $self->{state} = ACTIVE;
}

sub err {
    my ($self, @err) = @_;
    print STDERR __PACKAGE__.": ".join(" ", @err)."\n";
    return $self->write(pack('CC',5,255)) if($self->{state} < CONNECT);
}
1;
