package CGI::Scribe;

$SESSION_LENGTH = 16;
$CGI::Scribe::DEBUG = 0;

use strict;
use vars qw( $VERSION $AUTOLOAD $SESSION_LENGTH $SRAND );
use Carp;
use Storable qw( freeze thaw );
use MD5;
use CGI::Cookie;

require 5.004; # Depends on srand() supplying good seed 

$VERSION = '0.03';
$SRAND = 0;

sub new {
  my $class   = shift;
  my($session, $attr) = @_;

  $class = ref $class || $class;
  bless my $self = {}, $class;
 
  $self->initialize;

  if ($session) {
    croak "invalid session id $session" unless $session =~ /^[-A-Za-z0-9]+$/;
    $self->{session} = $session;
  }

  @$self{ keys %$attr } = values %$attr if $attr;  

  $self->_fetch_cookie if ref $self->{cookie};
  $self->_new_session unless $self->{session};

  $self;
}

sub initialize {
  my $self = shift;

  $self->{session}        = undef;
  $self->{cookie}         = undef;
  $self->{secret}         = 'eaven-hay and-ay e-thay earth-ay';
  $self->{session_length} = $SESSION_LENGTH;
  $self->{is_new}         = 0;
  $self->{_fetched}       = 0;
  $self->{_dirty}         = 0;
  $self->{_data}          = {};
  $self->{_cookie_data}   = {};
  $self->{debug}          = $CGI::Scribe::DEBUG;

  $self->{autoload}       = {
                              session_length => 1,
                              session        => 1,
                              secret         => 1,  
                              debug          => 1,
                              is_new         => 1,
                            };
}

sub version { $VERSION }

sub _debug {
  my $self = shift;
  my($msg, $level) = @_;

  $level ||= 1;
  $msg = "[$self->{session}] $msg" if $self->{session};
  warn ref $self, " $msg\n" if $self->{debug} >= $level; 
}

sub _fetch_cookie {
  my $self = shift;

  my($mac, $session, $frozen) = $self->{cookie}->value;
  return undef unless $mac and $session;
  # If the session is defined but doesn't match the cookie, then ignore cookie 
  return undef if $self->{session} and $self->{session} ne $session;

  # Check the Message Authentication Code (MAC)  
  my $mac_check = MD5->hexhash($self->{secret} . 
                    MD5->hexhash(join '', $self->{secret}, $session, $frozen));
  return undef unless $mac eq $mac_check;

  # Thaw the session data
  $self->{session} = $session;
  # Convert the hex data to binary
  my $thawed = eval { thaw( pack 'H*', $frozen ) }; 
  croak "error thawing session in cookie: $@" if $@ or ref $thawed ne 'HASH';

  foreach my $key (keys %$thawed) {
    $self->{_cookie_data}{$key} = 1; # keep track of what was in cookie
    $self->{_data}{ $key } = $thawed->{ $key };
  }

  if ($self->{debug}) {
    $self->_debug('fetched from cookie', 1);
    foreach my $key (keys %$thawed) {
      $self->_debug("cookie data: $key=$thawed->{$key}", 2);
    }
  }

  1; 
}

sub _new_session {
  my $self = shift;
  my $seed = shift;

  # Perl 5.004 and later automatically call srand() with a "good" 
  # seed, if it hasn't been called already.  However, it seems to
  # happen at compile-time such that child processes generate
  # identical sequences.  We've added a flag so that we make sure to 
  # call srand() on the first invocation of this method.
  srand unless $SRAND++;

  $self->{session} = join '-',
                       substr(MD5->hexhash($self->{secret} . rand() . $seed), 
                              0, $self->{session_length}), time;

  $self->_debug('generated', 1) if $self->{debug};

  $self->{_fetched} = 1;
  $self->{_dirty}   = 0;
  $self->{is_new}   = 1;
  $self->{session};
}

sub _fetch { 
  my $self = shift;

  $self->{_fetched} = 1;
  $self->_debug('fetched from server', 1) if $self->{debug};
}

sub _store { 
  my $self = shift;

  $self->{_dirty} = 0;
  $self->_fetch unless $self->{_fetched};
  $self->_debug('stored on server', 1) if $self->{debug};
}

sub clear {
  my $self = shift;

  $self->{_data}    = {};
  $self->{_dirty}   = 1;
  $self->{_fetched} = 1;
  $self->_debug('cleared', 1) if $self->{debug};
}

sub param {
  my $self = shift;

  # If no arguments, return list of keys
  unless(@_) {
    $self->_fetch unless $self->{_fetched};
    return keys %{ $self->{_data} };
  }

  # If just one parameter named is supplied, return the value
  if (@_ == 1) {
    return $self->{_data}{ $_[0] } 
      if exists $self->{_data}{ $_[0] } or $self->{_fetched};
    $self->_fetch;
    return $self->{_data}{ $_[0] };
  }

  # If more than one parameter, they want to set value(s) 
  $self->{_dirty} = 1;
  $self->_fetch unless $self->{_fetched};
  my %hash = @_;
  @{ $self->{_data} }{ keys %hash } = values %hash;

  1;
}

sub exists {
  my $self = shift;

  return undef unless @_;
  return exists $self->{_data}{ $_[0] } 
    if exists $self->{_data}{ $_[0] } or $self->{_fetched};
  $self->_fetch;
  exists $self->{_data}{ $_[0] };
}

sub delete_param {
  my $self = shift;

  return unless @_;

  # We must make sure we've fetched, to protect ourselves from reading
  # the deleted value(s) later
  $self->_fetch unless $self->{_fetched};
  $self->{_dirty} = 1;

  foreach my $param (@_) {
    delete $self->{_data}{$param};
  }
}

sub cookie {
  my $self = shift;

  # If a hash reference is passed, it specifies all of the param names 
  # to place in the cookie.  If a list is passed, we include those
  # names *along with* whatever was previously stored in the cookie.
  my %params = map { $_ => 1 } 
               (ref $_[0] eq 'ARRAY' 
                  ? @{ $_[0] } 
                  : keys %{ $self->{_cookie_data} }, @_);
  my @params = grep { $self->exists( $_ ) } keys %params;
  
  unless ($self->{cookie}) {
    $self->{cookie} = new CGI::Cookie( -name => 'session' );
  }

  my $frozen = eval {
                 freeze( { map { $_ => $self->param($_) } @params } );
               };
  croak $@ if $@;
  $frozen = unpack 'H*', $frozen; 
  my $mac = MD5->hexhash($self->{secret} .
              MD5->hexhash(join '', $self->{secret}, $self->{session}, 
                           $frozen));
  $self->{cookie}->value([ $mac, $self->{session}, $frozen ]);  
  $self->{cookie};
}

sub DESTROY {
  my $self = shift;

  $self->_store if $self->{_dirty};
}

sub AUTOLOAD {
  my $self = shift;
  my $type = ref($self) || croak "autoload: $self is not an object";
  my $name = $AUTOLOAD;

  $name =~ s/.*://;
  return if $name eq 'DESTROY';
  croak "unknown autoload name '$name'" unless exists $self->{autoload}{$name};
  return (@_ ? $self->{$name} = shift : $self->{$name});
}                

sub TIEHASH { shift()->new( @_ ) }
sub STORE   { shift()->param( @_ ) }
sub DELETE  { shift()->delete_param( @_ ) }
sub CLEAR   { shift()->clear( @_ ) }
sub EXISTS  { shift()->exists( @_ ) }

sub FETCH {
  my $self = shift;
  my $key  = shift;
 
  return $self->{session} if $key eq '_session';
  $self->param( $key ); 
}

sub FIRSTKEY {
  my $self = shift;

  $self->_fetch unless $self->{_fetched};
  my $reset = keys %{ $self->{_data} };
  return each %{ $self->{_data} };
}

sub NEXTKEY { each %{ shift()->{_data} } }    


1;

__END__

=head1 NAME

CGI-Scribe - Perl extension for blah blah blah

=head1 SYNOPSIS

  use CGI-Scribe;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for CGI-Scribe was created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head1 AUTHOR

A. U. Thor, a.u.thor@a.galaxy.far.far.away

=head1 SEE ALSO

perl(1).

=cut
