package CGI::Scribe::DBI;

$MAX_TRIES = 100;

use strict;
use vars qw( @ISA $MAX_TRIES );
use Carp; 
use Storable qw( freeze thaw );
use DBI;
use CGI::Scribe;

@ISA = qw( CGI::Scribe );

sub new {
  my $class = shift;
  
  $class = ref $class || $class;
  return $class->SUPER::new( @_ );
}

sub initialize {
  my $self = shift;

  $self->SUPER::initialize;

  $self->{autoload}{db_source} = 1;
  $self->{autoload}{db_auth}   = 1;
  $self->{autoload}{db_table}  = 1;
  $self->{db_table} = 'sessions';
}

# XXX There's a weird problem, at least with perl 5.005_03,
#     DBI 1.06, and DBD::mysql 2.0217.  It appears that the database
#     handle is lost in our DESTROY() method -- as though the database
#     handle's destructor is being called before ours.  Adding
#     the InactiveDestroy parameter fixed it.  Even weirder, the
#     value of InactiveDestroy doesn't seem to matter -- either 0 or 1
#     fixed the problem.  It just needs to be there.  This should
#     be investigated.
#
#     UPDATE: weird things are still occuring with the inherited
#             destructor.  So for now, we're including all of the
#             necessary code in the subclass destructor and are not
#             calling our parent's.
sub _connect {
  my $self = shift;

  $self->{_dbh} = DBI->connect( $self->{db_source}, 
                                split(':', $self->{db_auth}, 2),
                                { RaiseError      => 0, 
                                  AutoCommit      => 1,
                                  InactiveDestroy => 0, 
                                } 
                              )
    or croak "unable to connect to database: $DBI::errstr";
}

sub _new_session {
  my $self = shift;

  # We don't need to do this here, since the call to SUPER::_new_session()
  # sets these values appropriately
  # 
  # $self->{_fetched} = 1;
  # $self->{_dirty}   = 0;
  # $self->{is_new}   = 1;

  $self->_connect unless ref $self->{_dbh};

  my $frozen = freeze( $self->{_data} );

  my $sth = $self->{_dbh}->prepare_cached("INSERT INTO $self->{db_table} 
    (session, session_data, created) VALUES(?, ?, ?)");

  # now create a new session, and make sure it's unique
  my $try  = 0;
  while(++$try <= $MAX_TRIES) {
    $self->{session} = $self->SUPER::_new_session( $self->{session} );
    last if $sth->execute( $self->{session}, $frozen, time );  
    $self->_debug('collision', 2) if $self->{debug};
  }
  $sth->finish;
  croak "unable to generate unique session id" if $try > $MAX_TRIES;

  $self->_debug('selected as new session', 1) if $self->{debug};

  $self->{session};
}

sub _fetch {
  my $self = shift;

  $self->{_fetched} = 1;

  $self->_connect unless ref $self->{_dbh};

  my $sth = $self->{_dbh}->prepare_cached("SELECT session_data FROM 
    $self->{db_table} WHERE session=?");
  $sth->execute( $self->{session} ) 
    or croak "error fetching session $self->{session}: $DBI::errstr";
  my $row = $sth->fetchrow_arrayref;
  $sth->finish;
  # If the fetch succeeded but was empty, return success
  defined $row or return 1;  

  my $thawed = eval { thaw( $row->[0] ) };
  defined $thawed and ref $thawed eq 'HASH' 
    or croak "error thawing session $self->{session}";

  foreach my $key (keys %$thawed) {
    $self->{_data}{ $key } = $thawed->{ $key };
  }  

  if ($self->{debug}) {
    $self->_debug('fetched from server', 1);
    foreach my $key (keys %$thawed) {
      $self->_debug("server data: $key=$thawed->{$key}", 2);
    }
  }             
         
  1; 
}

sub _store {
  my $self = shift;

  $self->_debug('storing on server', 1) if $self->{debug};

  $self->{_dirty} = 0;
  $self->_fetch unless $self->{_fetched};

  $self->_connect unless ref $self->{_dbh};
 
  my $frozen = eval { freeze( $self->{_data} ) };
  croak "error freezing session $self->{session}" unless defined $frozen;

  my $sth = $self->{_dbh}->prepare_cached("UPDATE $self->{db_table} SET
    session_data=? WHERE session=?");
  my $rows = $sth->execute( $frozen, $self->{session} );
  # XXX MySQL does not report all matched rows -- only changed rows
  croak "error updating session $self->{session}: $DBI::errstr"
    unless defined $rows;
  $sth->finish;

  # If we failed to update any rows, the session has probably expired
  # and we need to create it again.
  if ($rows < 1) {
    $self->_debug('missing on server -- recreating', 1) if $self->{debug};
    $sth = $self->{_dbh}->prepare_cached("INSERT INTO $self->{db_table}
      (session, session_data, created) VALUES(?, ?, ?)"); 
    $sth->execute( $self->{session}, $frozen, time ) 
      or croak "error recreating session $self->{session}: $DBI::errstr";
    $sth->finish;
  }

  1;
}

sub DESTROY {
  my $self = shift;

  $self->_debug('destroying session object', 2) if $self->{debug};

  $self->_store if $self->{_dirty};
  $self->{_dbh}->disconnect if ref $self->{_dbh};
}

1;
