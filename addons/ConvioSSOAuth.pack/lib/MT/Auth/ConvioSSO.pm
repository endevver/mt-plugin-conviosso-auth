package MT::Auth::ConvioSSO;

=head1 NAME

MT::Auth::ConvioSSO

=head1 DESCRIPTION

An authentication driver for Movable Type/Melody which provides a bridge for
delegated authentication using Convio's single sign-on authentication API.
More information about the API can be found at
L<http://open.convio.com/api/#single_sign_on_api>.

=cut
use strict;
use warnings;
use base 'MT::Auth::MT';

use Data::Dumper;
use JSON;
use MT::Util qw( encode_url caturl );
use MT::Author qw( AUTHOR );
use Net::Convio::OpenAPI;
use MT::Plugin::ConvioSSOAuth::Util;
# use MT::Log::Log4perl qw( l4mtdump ); use Log::Log4perl qw( :resurrect ); our $logger;
use vars qw( $ERROR );

sub TRUE()       { 1 }
sub FALSE()      { 0 }
sub USER_AGENT() { 'Convio SSO Auth (Movable Type)/1.0' }

=head1 MT::Auth INHERITED METHODS

The following methods are inherited MT::Auth methods we've overridden.

=head2 can_recover_password

A boolean flag that identifies whether this authentication module provides a
password recovery function. This is only valid when passwords are locally
stored and managed.

B<Convio SSO auth default:> True - Local MT authors can recover their
passwords by normal means.  Convio authors will be redirected.

=cut
sub can_recover_password() { TRUE }

=head2 is_profile_needed

A boolean flag that identifies whether this authentication module expects the
local management of the user's profile.

B<Convio SSO auth default:>  True - B<FIXME - UNSURE ABOUT THIS>

=cut
sub is_profile_needed()    { TRUE }

=head2 password_exists

A boolean flag that identifies whether this authentication module utilizes a
password or not (that is, whether one is required for an account and stored
with the user profile).

B<Convio SSO auth default:> True - Passwords are stored on Convio's servers
for Convio user records but also in MT for MT user records

=cut
sub password_exists()      { TRUE }

=head2 delegate_auth

A boolean flag that identifies whether this authentication module provides a
delegate authentication system. This would be the case where MT itself does
not ask for authentication information, but instead defers to another web
service or protocol. Typically, a delegated authentication also involves using
request redirects to the authentication service when necessary.

B<Convio SSO auth default:> False - This is a dual-mode authentication system
so MT stays in control deferring to Convio in case proper auth could not be
found.

=cut
sub delegate_auth()        { FALSE }

=head2 can_logout

A boolean flag that identifies whether this authentication module allows for a
'Logout' link and logout mechanism within the application interface.

B<Convio SSO auth default:> True - Since Convio is only used to verify
authentication and not to store state, the user's logged in status is
persisted in the Movable Type database. When a user logs out, their MT session
must be invalidated.

=cut
sub can_logout()           { TRUE }

=head2 new_user

A method used in the login attempt to give chance to each authentication layer
to process the user who is going to be created upon logging in for the first
time. The method must return boolean value indicating whether or not the
method actually saved the new user to the database or not.

In MT::Auth::ConvioSSO, we use it simply to force the password to a non-usable
value before the user record is saved in the database. 

=cut
sub new_user {
    my $auth           = shift;
    my ( $app, $user ) = @_;
    my $external_id    = $app->request( 'external_id' ) || '';
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();
    ###l4p $logger->debug('NEW USER: ', l4mtdump($user));

    # Unless we have a Convio external_id, there's no data to sync
    return FALSE unless $external_id; # Means we didn't save the user

    my $user_cache = $app->request('convio_user_data') || {};
    my $udata      = $user_cache->{ $external_id } || {};
    ###l4p $logger->debug('$udata cache: ', l4mtdump($udata));

    # Provision user profile fields when defined and has content
    foreach my $fld ( keys %$udata ) {
        next unless defined $udata->{$fld} and $udata->{$fld} ne '';
        $user->$fld( $udata->{$fld} );
    }

    # Convio users get no local password
    $user->password( '(none)' );

    ###l4p $logger->debug('NEW USER + CONVIO: ', l4mtdump({
    ###l4p     user        => $user,
    ###l4p     external_id => $external_id,
    ###l4p }));

    $user->save or die "Could not save user: ".$user->errstr;
    $user->add_default_roles();
    return TRUE; # Means we didn't' save the user
}

=head2 fetch_credentials(\%context)

A routine that gathers login credentials from the context of the active
request provide in the 'C<app>' key of its hashref argument. 

It returns and returns key elements in a hashref. The hashref should contain
any of the following applicable key fields:

=over 4

=item * app - The handle to the active application.

=item * username - The username of the active user.

=item * password - The user's password.

=item * session_id - If a session-based authenication is taking place, store
the session id with this key.

=item * permanent - A flag that identifies whether or not the credentials
should be indefinitely cached.

=back

=cut
sub fetch_credentials {
    my $auth     = shift;
    my ($ctx)    = @_;
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();
    $ctx->{sso_required} = 1;
    # my $fallback = {%$ctx};
    my $creds    = $auth->login_credentials(@_)
                || $auth->session_credentials($ctx)
                || $auth->remote_session_credentials( $ctx );
                # || $fallback;
    return $creds;
}

sub session_credentials {
    my $auth = shift;
    my ($ctx) = @_;
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();

    my $app = $ctx->{app} or return;
    my $cookies = $app->cookies;
    if ($cookies->{$app->user_cookie}) {
        my ($user, $session_id, $remember) = split /::/, $cookies->{$app->user_cookie}->value;
        ###l4p $logger->debug('COOKIE: ', l4mtdump({ %$ctx, username => $user, session_id => $session_id, permanent => $remember, auth_type => 'MT' }));
        return { %$ctx, username => $user, session_id => $session_id, permanent => $remember, auth_type => 'MT' };
    }
    return undef;
}


=head2 validate_credentials(\%context)

This method takes the authentication context returned by
C<MT::Auth::ConvioSSO::fetch_credentials> and determines if it is valid. It is
also ultimately responsible for assigning the active user if the credentials
are correct although the actual assignment is done in lower-level method.

=cut
sub validate_credentials {
    my $self       = shift;
    my ( $ctx )    = @_;
    my $app        = $ctx->{app};
    my $q          = $app->query;
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();

    $ctx->{auth_result} = MT::Auth::UNKNOWN(); # Default status

    #### SINGLE-SIGNON REDIRECT
    # Mode handler for users who are already authenticated locally
    # but who were redirected to Convio's singleSignOn method to
    # complete the universal authentication.
    return $self->conviosso_response( @_ )
        if $app->mode eq 'conviosso_response';

    ########################################################
    ####   USER CREDENTIALS VALIDATION/AUTHENTICATION   ####
    ########################################################    
    #### REMOTE AUTHENTICATION
    # If the external_id key is populated, we have either
    #   * A user with an alredy active remote session on Convio
    #   * Fallback validation for a user whose credentials
    #     were invalid for local authentication
    if ( $ctx->{external_id} ) {

        # ACTIVE REMOTE SESSION: At this point we have a user with an
        # active remote Convio session. Perform auto-login and user lookup
        $self->validate_remote_credentials( $ctx );

    }
    #### LOCAL AUTHENTICATION
    # All other users get run through local authentication
    # to check for session_id and/or incoming login credentials
    else {
        $self->validate_local_credentials( $ctx );
    }


    ########################################################
    ####           AUTHENTICATION RESPONSE              ####
    ########################################################
    # First dispatch any redirects that are pending
    return $ctx->{auth_result}
        if $ctx->{auth_result} == MT::Auth::REDIRECT_NEEDED();

    # Users who have an external_id but who are authenticated
    # using their local MT credentials need a redirect to Convio's
    # singleSignOn method to complete the universal auth
    # return $self->redirect_single_signon( $ctx )
    #     if eval { $app->user->external_id } and $ctx->{sso_required};

    ###l4p $logger->info('App->user: ', l4mtdump( $app->user ));
    ###l4p $logger->info("Returning auth_result from validate_credentials: "
    ###l4p     .$ctx->{auth_result});

    # For all else, return the authentication result
    return $ctx->{auth_result};
}

sub validate_session_credentials {
    my $self = shift;
    my ( $ctx ) = @_;
    my $app     = $ctx->{app};
    my $q       = $app->query;
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();
    my $username = $ctx->{username};
    my $password = $ctx->{password};

}
=head2 invalidate_credentials(\%context)

A routine responsible for clearing the active logged-in user both
locally and at Convio. The latter is performed with a redirect.

=cut
sub invalidate_credentials {
    my $self = shift;
    my ( $ctx ) = @_;
    my $app     = $ctx->{app};
    my $q       = $app->query;
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();

    return if $q->param('ts') and $q->param('signature');

    $self->SUPER::invalidate_credentials( @_ );

    # No need to do Convio log out an MT account with no Convio user assigned
    return unless $app->user && ! $app->user->external_id;

    $self->init_convio( $ctx );

    # Client only
    # https://secure2.convio.net/organization/site/CRConsAPI?
    #   method=logout
    #   &api_key=value 
    #   &v=value 
    #   [ &center_id=value ] 
    #   [ &error_redirect=value ] 
    #   [ &redirect=value ] 
    #   [ &response_format=xml | json ] 
    #   [ &sign_redirects=value ] 
    #   [ &source=value ] 
    #   [ &sub_source=value ] 
    #   [ &success_redirect=value ] 
    #   [ &suppress_response_codes=value ]

    my $return_url = sub {
          $app->base
        . $app->return_uri 
        . $app->make_return_args
    };

    my ($url, $post) = $ctx->{convio_api}->format_call(
        servlet          => 'client',  # Uses the Convio client API endpoint
        method           => 'logout',
        redirect         => $return_url->()
    );
    return $app->redirect(  
        $url . $ctx->{convio_api}->client->buildQuery( $post )
    );
}

=head1 MT::Auth DEFERRED METHODS

=head2 session_credentials(\%context)

A routine that attempts to discover and extract credentials from an active
user session stored in the user cookie

MT::Auth::ConvioSSO overrides this session simply to update the C<auth_type> from
C<MT> to C<ConvioSSOAuth>.

=head2 is_valid_password($author, $password, $crypted, \$error_ref)

A routine that determines whether the given password is valid for the author
object supplied. If the password is already processed by the 'crypt' function,
the third parameter here will be positive. The \$error_ref is a reference to a
scalar variable for storing any error message to be returned to the
application. The routine itself should return 1 for a valid password, 0 or
undef for an invalid one.

=head2 login_form

A method that returns a snippet of HTML code for displaying the necessary
fields for logging into the MT application.


=head1 MT::Auth::ConvioSSO CUSTOM METHODS

=head2 remote_session_credentials( \%context )

This is a fallback discovery method called by fetch_credentials if discovery
of local credentials or session fails. Similar to the inherited
session_credentials method, this method attempts to extract credentials from
an active B<Convio> user session.

For a valid user, this method will find credentials if the current request is a redirect response from the C<singleSignOn> API method call initiated in  the C<redirect_single_signon> method.

If the user has a remote session, the C<cons_id> query string parameter will
contain an integer. If no session exists, C<cons_id> will be set to C<0>.

Like all redirect responses, we must verify the Convio created signature to
ensure that we eliminate the possibility of replay attacks and URL tampering.

=cut
sub remote_session_credentials {
    my $self        = shift;
    my ( $ctx )     = @_;
    my $app         = $ctx->{app} or return;
    my $q           = $app->query;
    my $external_id = $q->param('cons_id') or return;
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();

    return unless $self->verify_query_signature( $ctx );

    return {
        %$ctx,
        external_id => $external_id,
        auto_login  => 1,
        permanent   => $ctx->{permanent},
        auth_type   => 'ConvioSSO',
    };
}

=head2 validate_remote_credentials( \%context )

This branch of the C<validate_credentials> method deals with requests in which
the external_id parameter is populated indicating that we have a user presented 
as a Convio user.

If a password is provided, we attempt to log the user in. Otherwise, the user 
is assumed to be authenticated from a previous call.

=cut
sub validate_remote_credentials {
    my $self    = shift;
    my ( $ctx ) = @_;
    my $app     = $ctx->{app};
    my $q       = $app->query;
    my $ext_id  = $ctx->{external_id} or return;
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();

    $self->init_convio( $ctx );
    # $logger->debug('$ctx in validate_remote_credentials: ', l4mtdump($ctx));

    # FALLBACK: If a password is supplied we attempt to log the user
    # in via Convio's login() API method for remote auth.
    if ( $ctx->{password} ) {
        unless ( $self->remote_login( $ctx ) ) { # All failures return undef
            $ctx->{auth_result} = MT::Auth::UNKNOWN();
            return;
        }
    }

    unless ( $ctx->{auto_login} ) {  # Sanity check
        $ctx->{auth_result} = MT::Auth::UNKNOWN();
        return $self->error(
            "Encountered auto_login code when auto_login is not set"
        );
    }

    # Store external_id in request object
    # This could have changed in the remote_login method
    $app->request( 'external_id', $ctx->{external_id} );

    ####################################################
    ####     ACTIVE REMOTE SESSION AUTO-LOGIN       ####
    ####    Find the author that matches this       ####
    ####    external_id and create local session    ####
    my @authors = MT->model('author')->load({
        external_id => $ctx->{external_id},
        $ctx->{user_id} ? (id => $ctx->{user_id}) : ()
    });
                                        # type => AUTHOR, auth_type => 'MT'
    # $logger->info('LOADED AUTHOR(S): ', l4mtdump(\@authors));

    my $author = shift @authors;
    if ( @authors ) { # Sanity check
        die "Multiple authors exist with Convio Constituent ID $ext_id. "
          . "Please notify your system administrator immediately.";
        # TODO Email the system administrator directly
    }

    $app->user or $app->user( $author );

    $self->synchronize_user({ ctx => $ctx, author => $author });

    $logger->warn('NO AUTHOR, NEW USER: ', l4mtdump( $author ))
        unless $author && ref($author);

    $ctx->{sso_required} = FALSE();
    $ctx->{auth_result}  = ref $author  ? MT::Auth::NEW_LOGIN()
                                        : MT::Auth::NEW_USER();
}

=head2 validate_local_credentials( \%context )

This method deals with users who are most likely local authors.  However, if
local authentication fails, we retry the request as a remote request by recalling
C<validate_credentials>.

=cut
sub validate_local_credentials {
    my $self       = shift;
    my ( $ctx )    = @_;
    my $app        = $ctx->{app};
    my $q          = $app->query;
    my $user_class = $app->user_class;
    my $username   = $ctx->{username};
    my $password   = $ctx->{password};
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();

    ###################################
    #### NATIVE MT AUTH VALIDATION ####
    # Run normal MT authentication to check for MT login credentials
    # If login is successful, $app->user will be populated with a valid user
    $ctx->{auth_result} = $self->SUPER::validate_credentials(@_);
    ###l4p $logger->debug('Native Auth: ', l4mtdump({auth_result => $ctx->{auth_result}, user => $app->user||'UNDEF' }));

    # If the credentials were invalid, they may be intended for remote auth
    # Switch the value from username to external_id and re-validate
    if (   $ctx->{auth_result} == MT::Auth::INVALID_PASSWORD()
        or $ctx->{auth_result} == MT::Auth::UNKNOWN() ) {

        if ( defined $username and $username ne '' ) {
            # load author from db
            my ($author) = $user_class->search({
                name => $username,
                type => AUTHOR,
                auth_type => 'ConvioSSO'
            });
            if ($author) {
                if ($ctx->{session_id}) {
                    $app->user($author);
                    $ctx->{auth_result} = MT::Auth::SUCCESS();
                }
                else {
                    my $error;
                    if ($author->is_valid_password($password, 0, \$error)) {
                        $app->user($author);
                        $self->synchronize_user({ ctx => $ctx, author => $author });
                        $ctx->{auth_result} = MT::Auth::NEW_LOGIN();
                    } else {
                        $ctx->{user_id} = 0;
                        $ctx->{external_id} = delete $ctx->{username};
                        $ctx->{auth_result}
                            = $self->validate_credentials( $ctx );
                    }
                }
            }
        }

         if ( ! $app->user ) {
             $ctx->{auth_result}
                 = $self->redirect_remote_session_test( $ctx );
         }
     }

    # If we successfully validate the user's credentials,
    # cache the user object in the auth context hash
    if ( my $user = $app->user ) {
        $ctx->{user}        = $user;
        $ctx->{user_id}     = $user->id;            # Assign these properties
        $ctx->{external_id} = $user->external_id;   # for lookup convenience
    }

    # Return the auth_result which could be successful or not
    return $ctx->{auth_result};
}

=head2 conviosso_response( \%context )

This authenticated mode handler receives the redirect from Convio's
C<singleSignOn> API method call sent by C<redirect_single_signon>.

=cut
sub conviosso_response {
    my $self             = shift;
    my ($ctx)            = @_;
    my $app              = $ctx->{app};
    my $q                = $app->query;
    $ctx->{sso_required} = FALSE();
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();

    $self->verify_query_signature( $ctx )
        or return MT::Auth::UNKNOWN();

    my $data = $self->load_cv_session( $q->param('session_id') );
    # $logger->debug('session data: ', l4mtdump($data));

    # FIXME NOT SURE ABOUT ALL OF THIS
    $ctx->{username}   ||= $data->{user_id}
                       ||  $data->{external_id};
    $ctx->{external_id}  = $data->{external_id};
    $ctx->{user_id}      = $data->{user_id};
    $app->request( 'external_id', $data->{external_id} );

    return $ctx->{session_id}               ? MT::Auth::SUCCESS()
         : $ctx->{last_session}{user_id}    ? MT::Auth::NEW_LOGIN()
                                            : MT::Auth::NEW_USER();
}

=head2 synchronize_user( \%{ ctx => \%context, author => $author } )

This method is called by C<validate_remote_credentials> when we have a user
who is both a Convio and local MT user. This method attempts to pull
information from Convio about the user via the C<getUser> API method and
update the local user record.

=cut
sub synchronize_user {
    my $self     = shift;
    my ( $args ) = @_;
    my $ctx      = $args->{ctx};
    my $user     = $args->{author};
    my $app      = $ctx->{app};
    my $ext_id   = $ctx->{external_id}  ? $ctx->{external_id}
                 : $user                ? $user->external_id
                                        : undef;
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();

    return unless $ext_id;

    # Get user data cache if one exists (i.e., under FastCGI)
    # Return the data if we have already polled this user
    my $user_cache = $app->request('convio_user_data') || {};
    return $user_cache->{ $ext_id }
        if $user_cache->{ $ext_id };

    # Otherwise make the call to Convio for the user profile data
    my $response = $ctx->{convio_api}->make_call(
        servlet        => 'server',  # Uses the Convio server API endpoint
        method         => 'getUser',
        login_name     => $app->config('ConvioSSOAdminUsername'),
        login_password => $app->config('ConvioSSOAdminPassword'),
        cons_id        => $ext_id,
    );

    ####################################
    ####   JSON RESPONSE DECODING   ####
    my $result = eval {
        # line __LINE__ __FILE__
        my $res = $ctx->{json_hdlr}->decode( $response );
        ###l4p $logger->info('res: ', l4mtdump($res));
        $res->{getConsResponse};
    };
    ###l4p $logger->info('getUser: ', l4mtdump({ result => $result }));

    unless ( $result ) {
        return $self->error("Could not synchronize user data: $@");
    }
    
    # Map Convio user profile fields to MT user profile fields
    my $nickname
        = join( ' ', grep { defined } map { $result->{name}{$_} }
                        qw( first middle last suffix prof_suffix ));

    my $username = $user ? $user->name
                 : $result->{user_name} ? $result->{user_name}
                                        : $ext_id;
    my $mapped_fields = {
        name             => $username,
        nickname         => $nickname                         || '',
        email            => $result->{email}{primary_address} || '',
        external_id      => $result->{cons_id}                || '',
        convio_member_id => $result->{member_id}              || '',
        convio_user_name => $result->{user_name}              || '',
        url              => $result->{work_web_page}
                         || $result->{home_web_page}          || '',
    };

    if ( $user and $user->id ) {
        # Update user profile fields when defined and has content
        foreach my $fld ( keys %$mapped_fields ) {
            next unless defined $mapped_fields->{$fld}
                    and $mapped_fields->{$fld} ne '';
            $user->$fld( $mapped_fields->{$fld} );
        }
        $user->save
            or die "Error saving synchronized user data: ".$user->errstr;
        $ctx->{username} ||= $user->name;
    }
    #### CACHE NEW USER DATA FOR new_user()
    else {
        $ctx->{username} ||= $mapped_fields->{name};
        $user_cache->{ $ctx->{external_id} } = $mapped_fields;
        $app->request( 'convio_user_data', $user_cache );
    }
    return $mapped_fields;
}

=head2 remote_login( \%context )

We verify the signature similarly to the way we verify signed redirects:
Append the cons_id, timestamp, and Convio API
secret key into a single text string (without any delimiters between
them) and compute its hash value. This value should match the
signature provided in the API response. 

=cut
sub remote_login {
    my $self    = shift;
    my ( $ctx ) = @_;
    my $app     = $ctx->{app};
    my $q       = $app->query;
    my $ext_id  = $ctx->{external_id};
    my $pass    = $ctx->{password};
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();

    $self->init_convio( $ctx );

    unless ( defined $ext_id and defined $pass ) {
        return $self->error( "Missing remote login credential: "
            . join(', ', grep { defined $ctx->{$_} }
                qw(external_id password)));
    }

    my ($json_response) = $ctx->{convio_api}->make_call(
        servlet        => 'server',  # Uses the Convio client API endpoint
        method         => 'login',
        login_name     => $app->config('ConvioSSOAdminUsername'),
        login_password => $app->config('ConvioSSOAdminPassword'),
        user_name      => $ctx->{external_id},
        email          => $ctx->{email},
        password       => $ctx->{password},
        remember_me    => $ctx->{remember_me},
    );

    my $result = eval {
        # line __LINE__ __FILE__
        my $struct = $json_response || $ctx->{convio_api}->errstr;
        my $res = $ctx->{json_hdlr}->decode( $struct );
        ###l4p $logger->info('result: ', l4mtdump($res));
        $res->{loginResponse} || $res->{errorResponse};
    };

    # The code and message parameters are only populated in the 
    # errorResponse struct and indicate that an error has occurred
    #       errorResponse":{
    #         "code":402,
    #         "message":"BLAH BLAH BLAH"
    #       }
    if ( $result->{code} && $result->{message} ) {
        return $self->error( $result->{message} );
    }

    #       loginResponse":{
    #         "signature":"d2584385fe2b6d5ff2f72b9bf6331d9c",
    #         "cons_id":"1001002",
    #         "token":null,
    #         "timestamp":"1287763970"
    #       }
    if ( $result->{cons_id} && $result->{signature} && $result->{timestamp}) {

        $result->{string} = $result->{cons_id} . $result->{timestamp};

        return unless $self->verify_query_signature( $ctx, $result );

        # Rearranging field values; since login with external_id worked
        # it means it's the username, not the external_/cons_id
        $ctx->{convio_user_name}  = $ctx->{external_id};
        $ctx->{external_id}       = $result->{cons_id};
        return $ctx->{auto_login} = 1;
    }

    return $self->error( 'Convio login method response did not fail '
                        .'but did not have the required fields. '
                        .$ctx->{json_hdlr}->encode( $result ));
}

=head2

This method is called when the user is locally authenticated but we need to
log them into Convio. It does so by redirecting the user to Convio's
C<singleSignOn> API method call to attempt/complete universal login.

The singleSignOn method uses a single sign-on token to log the site visitor in
to the site as a registered user. The user identification is embedded in the
token. The token is obtained by the external server by calling the
getSingleSignOnToken, login, or authenticateUser API methods. Use this method
when calling from a Web Client.

=cut
##############################################################
#### NOTE:  At this point, we have a valid Convio user who
####        may also be a valid MT user.  First, we save this
####        state in a short-term MT::Session record and 
####        then redirect them to Convio using the SSO auth
####        token so they can be logged in.  Convio will 
####        redirect back to us using the session ID which
####        MT::Plugin::ConvioSSOAuth will receive.
#############################################################
sub redirect_single_signon {
    my $self    = shift;
    my ( $ctx ) = @_;
    my $app     = $ctx->{app};
    my $q       = $app->query;
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();

    # return $self->redirect_unauthenticated( $ctx )
    #     unless $user or defined $q->param('current_cons_id');
    # unless ( $ctx->{cons_id} ) {
    #     return $ctx->{is_login} ? $ctx->{auth_result}
    #                             : MT::Auth::UNKNOWN();
    # }

    # Make autheticated Convio Server API to retrieve auth token. If the
    # call returns undef, we had a authentication failure
    my $sso_auth_token = $self->get_sso_auth_token( $ctx );

    # Save the context in a session record so that we can
    # pick up easily when the response comes in
    my $session = $self->save_cv_session( $ctx );

    my ($url, $post) = $ctx->{convio_api}->format_call(
        servlet          => 'client',  # Uses the Convio client API endpoint
        method           => 'singleSignOn',
        sso_auth_token   => $ctx->{sso_auth_token},
        remember_me      => $ctx->{remember_me},
        redirect         => $app->base
                          . $app->mt_uri(
                              mode => 'conviosso_response',
                              args => {
                                  session_id => $session->id,
                              }
                            )
                          . '&code=>${errorResponse/code}'
                          . '&message=${errorResponse/message}',
    );
    unless ( $url && $post ) {
        die "Could not format authenticated Convio redirect ($url, $post): "
            . $ctx->{convio_api}->errstr;
    }

    $app->redirect(  
        $url . $ctx->{convio_api}->client->buildQuery( $post )
    );

    return $ctx->{auth_result} = MT::Auth::REDIRECT_NEEDED();
}

=head2 redirect_remote_session_test

This method redirects a user to Convio to test for authentication. 

FIXME When is this called?

=cut
sub redirect_remote_session_test {
    my $self = shift;
    my ( $ctx ) = @_;
    my $app = $ctx->{app};
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();

    my $return_url = sub {
          $app->base
        . $app->return_uri 
        . $app->make_return_args
        . '&current_cons_id='
        . (shift || 0)
    };

    my ($url, $post) = $ctx->{convio_api}->format_call(
        servlet          => 'client',  # Uses the Convio client API endpoint
        method           => 'loginTest',
        success_redirect => $return_url->('${loginResponse/cons_id}'),
        error_redirect   => $return_url->()
    );
    unless ( $url && $post ) {
        die "Could not format authenticated Convio redirect ($url, $post): "
            . $ctx->{convio_api}->errstr;
    }

    $app->redirect(  
        $url . $ctx->{convio_api}->client->buildQuery( $post )
    );

    ###l4p $logger->debug('REDIRECT: ', $app->{redirect});
    return $ctx->{auth_result} = MT::Auth::REDIRECT_NEEDED();
}

=head2 get_sso_auth_token

This method initiates a Convio server API call to the getSingleSignonToken
method which, given a cons_id, returns an authentication token which we can
use in a redirect to log the user into the remote system.

This token is only valid for the specific user and only for a limited time
(typically, a few minutes). To log in to the Convio system and visit most
pages, the token need only be presented one time to initiate the logged-in
session. However, if other API methods are used during the visit, this token
should be included in all API requests to verify that the API methods are
being called from a trusted source.

=cut
sub get_sso_auth_token {
    my $self = shift;
    my ($ctx) = @_;
    my $app = $ctx->{app};
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();

    $self->init_convio( $ctx );

    my $response = $ctx->{convio_api}->make_call(
        servlet        => 'server',  # Uses the Convio server API endpoint
        method         => 'getSingleSignOnToken',
        login_name     => $app->config('ConvioSSOAdminUsername'),
        login_password => $app->config('ConvioSSOAdminPassword'),
        cons_id        => $ctx->{user}->external_id
    );
    ###l4p $logger->info('getSingleSignOnToken response: '. ($response||''));
    die "getSingleSignOnToken failure: ".$ctx->{convio_api}->errstr
        unless $response;

    ###################################
    #### SSO AUTH TOKEN EXTRACTION ####
    # The SSO auth token is embedded in a JSON response, we eval this to 
    # gracefully handle exceptions related to decoding or unexpected data.
    my $sso_auth_token = eval {
        # line __LINE__ __FILE__
        my $result = $ctx->{json_hdlr}->decode( $response );
        ###l4p $logger->info('result: ', l4mtdump($result));
        $result->{getSingleSignOnTokenResponse}{token};
    };
    unless ( $sso_auth_token ) {
        die 'ConvioSSOAuth exception: Could not retrieve token '
          . 'from getSingleSignOnTokenResponse. '.$@;
    }
    ###l4p $logger->info('sso_auth_token: '. $sso_auth_token);

    return ( $ctx->{sso_auth_token} = $sso_auth_token );
}


=head2 verify_query_signature

This method is called by any other which receives a response back from
Convio all of which are cryptographically signed to ensure that the call is 
valid and that its origin is Convio.

=cut
sub verify_query_signature {
    my $now            = time;
    my $self           = shift;
    my ($ctx, $result) = @_;
    my $app            = $ctx->{app};
    my $secret         = $app->config->ConvioSSOSecretAPIKey;
    my $q              = $app->query;
    my $ts             = $result->{timestamp} || $q->param('ts');
    my $sig            = $result->{signature} || $q->param('signature');
    my $qs             = $result->{string}    || $app->query_string;
    my $session_id     = $q->param('session_id');
    my $ts_diff        = ($now-$ts);
=pod
    The URL is signed by adding a timestamp to the query string. Then an
    MD5 or SHA-1 hash of the URL query string plus the
    CONVIO_API_SECRET_KEY are calculated and the result is appended to the
    query string.

    1. Pull that portion of the URL query string after the "?" and up to
    the argument "&signature=".
=cut

    $qs =~ s{^\??(.*?[\&;]signature=).*}{$1}sm
        unless $result->{string};    # Already fixed

=pod
    2. Append the secret key to that portion of the query string.
=cut
    $qs .= $secret;

=pod
    3. Generate the appropriate hash (MD5 or SHA-1) for that string.
=cut
    my $qs_hash = eval {
        require Digest::MD5;
        Digest::MD5::md5_hex($qs);
    };
    $@ and return $self->error( 
            'Error creating md5 hash of query string: '.$@ );

=pod
    4. Compare the hash with the value of the "signature" argument.

    5. Assuming that the values match, you can be confident that the URL
    was generated by Convio.

=cut

    unless ( $sig eq $qs_hash ) {
        my $error = "Signature did not match expected value";
        return $self->error( $error.": sig: $sig, qs_hash: $qs_hash" );
    }

=pod
    6. Compare the value of the "ts" argument in the URL with the current
    time from your system in seconds since 1/1/1970. The values should be
    close enough (within a few seconds provided your system clock is
    accurate) to ensure that this is not a replay attack.
=cut
    if ( $ts_diff > 5 or $ts_diff < -5 ) {
        return $self->error( 'Convio login redirect rejected due to '
                              . "timestamp mismatch (${ts_diff}s)."  );
    }

    return 1;
}

=head2 save_cv_session

This method is called immediately before any redirection to Convio and saves
the state of the current request.

=cut
sub save_cv_session {
    my ( $self, $ctx ) = @_;
    my $app            = $ctx->{app};
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();

    # CREATE OR REUSE CV SESSION
    my $session = MT->model('session')->get_by_key({
        kind => 'CV',   # CV == Convio authentication
        name => 'convio:'.($ctx->{external_id} || $ctx->{username}),
    });

    $session->id or $session->id( $app->make_magic_token() );

    # foreach (grep { $_ !~ m{^(convio_api|json_hdlr|app)$} } keys %$ctx) {
    #     $logger->info("$_: ", $ctx->{$_});
    #     $session->set( $_, $ctx->{$_} );
    # }

    $session->set( $_, $ctx->{$_} ) 
        foreach grep { $_ !~ m{^(convio_api|json_hdlr|app|user)$} }
                keys %$ctx;

    $session->set('return_uri', $app->return_uri);
    $session->set('return_args', $app->make_return_args);
    
    $session->start(time);
    ##l4p $logger->debug('SESSION pre_save: ', l4mtdump($session));
    $session->save;
    ##l4p $logger->debug('SESSION post_save: ', l4mtdump($session));
    $session;
}

=head2 load_cv_session( $session_id )

This method is called immediately after returning from any Convio redirect
and restores the state saved before the call was issued.

=cut
sub load_cv_session {
    my $self = shift;
    my ( $session_id ) = @_;
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();
    # LOAD CV SESSION saved in MT::Auth::ConvioSSO
    my $session = MT::Session::get_unexpired_value(
            30, { id => $session_id, kind => 'CV' }
        );
    if ( $session ) {
        my $data = $session->thaw_data();
        $session->remove();
        return $data;
    }
    # $logger->debug('$session: ', l4mtdump($session));
    # my $data = eval { $session->thaw_data() };
    # $logger->debug('$data: ', l4mtdump($data));
    # $data;
}


=head2 error

This error handler method is similar to MT::ErrorHandler except that it carries with
it enhanced context information for better logging.

=cut
sub error {
    my $pkg = shift;
    my $err = @_ ? $_[0] : 'Undefined error';
    my $msg = ref $err  ? $err->{message} : $err;
    if ( defined $msg ) {
        $msg .= "\n" if ( $msg ne '' ) && ( $msg !~ /\n$/ );
    }
    $err = {};
    $err->{message}      = __PACKAGE__.' error: '.$msg;
    $err->{description}  = '' unless defined $err->{description};
    $err->{description} .= delete $err->{stacktrace} || Carp::longmess();

    MT->instance->log({
        message     => $err->{message},
        description => $err->{description},
        level       => MT::Log::SECURITY(),
        category    => 'login_user',
    });

    if ( ref($pkg) ) {
        $pkg->{_errstr} = $err->{message};
    }
    else {
        $ERROR = $err->{message};
    }
    return;
}

=head2 init_convio

This method initializes and caches the Convio instance used to make the
remote calls, the JSON handler used for decoding the responses and various
bits of data to ease translation between the Convio API and Movable
Type/Melody

=cut
sub init_convio {
    my $self    = shift;
    my ( $ctx ) = @_;
    my $app     = $ctx->{app} or return;
    my $q       = $app->query;
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();

    return if defined $ctx->{convio_api};

    ###l4p $logger->info('Initializing convio API, handlers and params');
    
    # Initialize Convio API object, the JSON handler and other info
    $ctx->{convio_api}
        = MT::Plugin::ConvioSSOAuth::Util::convio_instance()
        or die "Could not initialize ConvioSSOAuth: "
             . MT::Plugin::ConvioSSOAuth->errstr;

    $ctx->{json_hdlr}   = JSON->new->utf8(1)
        or die "Could not initialize JSON handler: ".JSON->errstr;

    $ctx->{remember_me} = $ctx->{permanent}; # Quick alias to avoid heartache

}

1;

__END__

