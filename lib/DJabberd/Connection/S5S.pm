package DJabberd::Connection::S5S;
use strict;
use warnings;
use base 'Danga::Socket';

use constant WAITING => 0; # Server
use constant STARTED => 1; # Client
use constant AUTHEN  => 2; # Server
use constant REQUEST => 3; # Client
use constant CONNECT => 4; # Server/Client
use constant ACTIVE  => 5; # Server
use constant OPENED  => 6; # Client
use constant CLOSED  => 9; # Server/Client

use fields qw(buf srv state hash peers);

sub new {
    my ($class, $sock, $server) = @_;
    my $self = $class->SUPER::new($sock);
    $self->{srv} = $server;
    $self->{state} = WAITING;
    $self->log("Created",$self);
    return $self;
}

sub hash { $_[0]->{hash} }

sub event_read {
    my ($self) = @_;
    my $bfr = $self->read(40_000);
    return $self->close unless(defined $bfr);
    $self->log("Read: $bfr; State: ".$self->{state});

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

sub start {
    my ($self, $hash) = @_;
    
    $self->watch_write(1);
    return $self->err('Write')
	unless($self->write(pack('CCC', 5, 1, 0)));
    $self->{hash} = $hash;
    $self->watch_read(1);
    $self->log('Moving state to STARTED');
    $self->{state} = STARTED;
}

sub handshake {
    my ($self) = @_;
    if($self->{state} == WAITING) {
	my ($ver, $mn) = unpack('CC', $self->{buf});
	return $self->err('Ver:', $ver,'Met:',$mn)
	    unless($ver == 5 && $mn > 0);
	return if(length($self->{buf}) < ($mn + 2));
	my @ms = unpack("xxC$mn",$self->{buf});
	$self->{buf} = '';
	if(grep{$_==0}@ms) {
	    $self->log('Moving state to AUTHEN');
	    $self->{state} = AUTHEN;
	    $self->write(pack('CC',5,0)) || $self->write(undef);
	    return;
	}
	$self->write(pack('CC',5,255));
	return $self->err('No supported auth[0]');
    } elsif($self->{state} == STARTED) {
	my ($ver, $am) = unpack('CC', $self->{buf});
	return $self->err('Ver:', $ver,'Met:',$am)
	    unless($ver == 5 && $am == 0);
	$self->{buf} = '';
	$self->write(pack("C4 C/A* S", 5, 1, 0, 3, $self->hash, 0));
	$self->log('Moving state to REQUEST');
	$self->{state} = REQUEST;
    } elsif($self->{state} == AUTHEN || $self->{state} == REQUEST) {
	return if(length($self->{buf}) < 5);
	my ($ver, $cmd, $rsv, $at, $al) = unpack('C5', $self->{buf});
	my $sts = ($self->{srv} ? 1 : 0);
	return $self->err('Ver:',$ver,'Cmd:',$cmd,'Type:',$at,'AL:',$al)
	    unless($ver == 5 && $cmd == $sts && $at == 3 && $al >= 40);
	return if(length($self->{buf}) < 47); # 5 + $al + 2
	my ($hash, $port) = unpack("xxxx C/A* S", $self->{buf});
	return $self->err('Hash:',$hash,'Port:',$port)
	    unless($hash =~ /^[a-fA-F0-9]+$/ && $port == 0);
	$self->log('Moving state to CONNECT');
	$self->{state} = CONNECT;
	if($self->{srv}) {
	    $self->{hash} = $hash;
	    $self->write(pack('CCCC C/A* S',5,0,0,3,$hash,0));
	    # Now broadcast our socket to all vhosts
	    DJabberd->foreach_vhost(sub {
		my ($vhost) = @_;
		$vhost->hook_chain_fast('GetPlugin',
		    [ 'DJabberd::Component::S5P' ],
		    {
			set => sub { $_[1]->add_conn($self); }
		    });
	    });
	} else {
	    return $self->err('Hash:',$hash,'<>',$self->hash) unless($hash eq $self->hash);
	}
    }
}

sub activate {
    my ($self, @peers) = @_;
    $self->{buf} = undef;
    croack('Cannot activate from '.$self->{state}) unless($self->{state} == CONNECT);
    $self->{peers} = \@peers;
    $self->{state} = ACTIVE;
}

sub open {
    my ($self) = @_;
    $self->{buf} = undef;
    croack('Cannot open from '.$self->{state}) unless($self->{state} == CONNECT);
    $self->{state} = OPENED;
}

sub log {
    my ($self, @log) = @_;
    unshift(@log, ($self->{srv} ? 'Server:':'Client:'));
    $DJabberd::Component::S5P::logger->debug(join(" ", @log));
}

sub err {
    my ($self, @err) = @_;
    $self->log(@err);
    $self->{state} = CLOSED;
    return $self->write(pack('CC',5,255)) if($self->{state} < CONNECT);
}
1;
