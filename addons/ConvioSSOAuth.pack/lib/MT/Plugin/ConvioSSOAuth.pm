package MT::Plugin::ConvioSSOAuth;

use strict;
use warnings;
use base qw( MT::Component Class::Accessor Class::Data::Inheritable );
use Carp;

use MIME::Base64;
use XML::Simple;
use Date::Parse;
use MT::Util qw( encode_html );

# use MT::Log::Log4perl qw( l4mtdump ); use Log::Log4perl qw( :resurrect ); our $logger;

__PACKAGE__->mk_accessors(qw( api_key ));
__PACKAGE__->mk_classdata( 'sign_redirects'  => 'true' );
__PACKAGE__->mk_classdata( 'response_format' => 'json' );
__PACKAGE__->mk_classdata( 'v'               => '1.0' );

sub external_user_management {
    my $mgr = shift;
    return $mgr->set_internal( 'ExternalUserManagement', @_ ) if @_;
    return 0 if $mgr->AuthenticationModule ne 'MT';
    return $mgr->get_internal('ExternalUserManagement');
}

sub tmpl_param_edit_author {
    my ( $eh, $app, $param, $tmpl ) = @_;
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();

    return unless ref $tmpl and $tmpl->isa('MT::Template');

    my $q      = $app->query;
    my $type   = $q->param('_type');
    my $class  = $app->model($type) or return;
    my $id     = $q->param('id');
    my $author = $app->user;

    my $auth_mode = $app->config('AuthenticationModule');
    my ($pref) = split /\s+/, $auth_mode;
    $param->{"auth_mode_$pref"} = 1;


    # $param->{new_user_external_auth} = 1;
    # # $param->{ 'auth_mode_' . $cfg->AuthenticationModule } = 1;
    # $author->external_id(MT::Author->pack_external_id( $param{user_external_id})) if exists $param{user_external_id};

    my $cfg = $app->config();
    if ( $cfg->AuthenticationModule eq 'ConvioSSO' ) {
        my $exid = $author->external_id;
        $exid = '' unless defined $exid;
        if ( $exid !~ m/[\x00-\x1f\x80-\xff]/ ) {
            $param->{external_id} = $exid;
        }
    }

    head_insertion(
        $app, $param, $tmpl, q(
        <link rel="stylesheet" href="<$mt:PluginStaticWebPath component="ConvioSSOAuth"$>/ConvioSSOAuth.css" type="text/css" media="screen" charset="utf-8"> )
    );


#     my $obj_promise = MT::Promise::delay(
#         sub {
#             return $class->load($id) || undef;
#         }
#     );
#     my $obj;
#     if ($id) {
#         $obj = $obj_promise->force()
#             or return $app->error(
#             $app->translate(
#                 "Load failed: [_1]",
#                 $class->errstr || $app->translate("(no reason given)")
#             )
#             );
#         if ( $type eq 'author' ) {
#             require MT::Auth;
#             if ( $app->user->is_superuser ) {
#                 if ( $app->config->ExternalUserManagement ) {
#                     if ( MT::Auth->synchronize_author( User => $obj ) ) {
#                         $obj = $class->load($id);
#                         ## we only sync name and status here
#                         $param->{name}   = $obj->name;
#                         $param->{status} = $obj->status;
#                         if ( ( $id == $author->id ) && ( !$obj->is_active ) )
#                         {
#                             ## superuser has been attempted to disable herself - something bad
#                             $obj->status( MT::Author::ACTIVE() );
#                             $obj->save;
#                             $param->{superuser_attempted_disabled} = 1;
#                         }
#                     }
#                     my $id = $obj->external_id;
#                     $id = '' unless defined $id;
#                     if ( length($id) && ( $id !~ m/[\x00-\x1f\x80-\xff]/ ) ) {
#                         $param->{show_external_id} = 1;
#                     }
#                 }
#                 delete $param->{can_edit_username};
#             }
#             else {
#                 if ( !$app->config->ExternalUserManagement ) {
#                     $param->{can_edit_username} = 1;
#                 }
#             }
#             $param->{group_count} = $obj->group_count;
#         }
#     }
#     else {    # object is new
#         if ( $type eq 'author' ) {
#             if ( !$app->config->ExternalUserManagement ) {
#                 if ( $app->config->AuthenticationModule ne 'MT' ) {
#                     $param->{new_user_external_auth} = '1';
#                 }
#             }
#         }
#     }
#     if ( $type eq 'author' ) {
#         $param->{'external_user_management'}
#             = $app->config->ExternalUserManagement;
#     }
#     my $element = $tmpl->getElementById('system_msg');
#     if ($element) {
#         my $contents = $element->innerHTML;
#         my $text     = <<EOT;
# <mt:if name="superuser_attempted_disabled">
#     <mtapp:statusmsg
#         id="superuser-atempted-disabled"
#         class="alert">
#         <__trans_section component="enterprise"><__trans phrase="Movable Type Enterprise has just attempted to disable your account during synchronization with the external directory. Some of the external user management settings must be wrong. Please correct your configuration before proceeding."></__trans_section>
#     </mtapp:statusmsg>
# </mt:if>
# EOT
#         $element->innerHTML( $text . $contents );
#     }
#     $tmpl;
} ## end sub tmpl_param_edit_author

sub tmpl_param_chromeless_header {
    my $cb = shift;
    my ( $app, $param, $tmpl ) = @_;
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();
    ###l4p $logger->debug('$app->mode: ', $app->mode);

    # $logger->debug('js_include: ', $param->{js_include});
    # my $nodes = $tmpl->getElementsByName('js_include') || [];
    # $logger->debug('$nodes: ',l4mtdump($nodes));
    # # $param->{js_include} .= "\n// JAYBO\n";
    #
    # $html_head = $tmpl->createElement('setvarblock', {
    #     name => 'js', append => 1
    # });
    #
    # # Inject our code into the block
    # $html_head->innerHTML($head_code);
    #
    # # Insert the setvarblock just before the header include
    # $tmpl->insertBefore($html_head, $header_include);
    ###l4p $logger->debug('$param: ', l4mtdump($param));
    $param->{js_include} = '' unless defined $param->{js_include};
    $param->{js_include} .= "HELLO";
} ## end sub tmpl_param_chromeless_header

# This method should no longer be used
sub load_cv_session {
    my ($session_id) = @_;
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();
    # LOAD CV SESSION saved in MT::Auth::ConvioSSO
    my $session = MT::Session::get_unexpired_value( 30,
                                        { id => $session_id, kind => 'CV' } );
    if ($session) {
        my $data = $session->thaw_data();
        $session->remove();
        return $data;
    }

    # $logger->debug('$session: ', l4mtdump($session));
    # my $data = eval { $session->thaw_data() };
    # $logger->debug('$data: ', l4mtdump($data));
    # $data;
}

# This method should no longer be used
sub response {
    die "DIE DIE DIE DIE";
    my $app        = shift;
    my $now        = time;
    my $q          = $app->query;
    my $ts         = $q->param('ts');
    my $ts_diff    = ( $now - $ts );
    my $sig        = $q->param('signature');
    my $session_id = $q->param('session_id');
    ( my $qs = $app->query_string ) =~ s{^\??(.*?)[\&;]signature.*}{$1};
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();
    ###l4p $logger->warn('Response timestamp is '.($now-$ts).' seconds ahead of our server time');
    return $app->error('Invalid Convio response')
      if ( $ts_diff > 5 or $ts_diff < -5 );

    my $sess_data = load_cv_session($session_id);

    # $logger->debug('sess_data: ', l4mtdump($sess_data));
    use Data::Dumper;
    return Dumper(
               { now => $now, 'q' => $q, ts => $ts, sig => $sig, qs => $qs } )

} ## end sub response

# This method should no longer be used
sub head_insertion {
    my ( $app, $param, $tmpl, $head_code ) = @_;
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();

    # my $head_code = _compile_head_code();

    my $html_head;

    # First, attempt to find an existing html_head mt:Var declaration
    # as it's easy to append to.
    my $nodes = $tmpl->getElementsByName('html_head') || [];

    # $logger->debug('$nodes 1: ', l4mtdump($nodes));

    # Filter out any nodes which are not mt:SetVarBlock's
    $nodes = [ grep { $_->nodeName eq 'setvarblock' } @$nodes ];

    # $logger->debug('$nodes 2: ', l4mtdump($nodes));

    # If we found at least one setvarblock html_head node, we can
    # have a place to put the code.
    if (@$nodes) {
        ###l4p $logger->warn('NODE FOUND: EXISTING SETVARBLOCK');

        # We reverse the nodes and search from the bottom up since we want
        # to inject our code as late as possible in the final HTML output
        foreach my $node ( reverse @$nodes ) {

            # We skip prepends for the same reason above
            next if $node->getAttribute('prepend');
            $html_head = $node;
            last;
        }

        # If $html_head is still unset, use the first since that would
        # be the final html_head in the output. (i.e. all are prepends)
        $html_head ||= $nodes->[0];

        # Append the code to the innerHTML of the setvarblock
        $html_head->innerHTML(
                          join( "\n\n", $html_head->innerHTML, $head_code ) );

        return;    # Short circuit the rest of the subroutine
    } ## end if (@$nodes)

    # At this point, no setvarblock html_head declarations exist. Instead
    # we have to create our own setvarblock and insert it directly before
    # the <mt:include module="include/header.tmpl">
    $nodes = $tmpl->getElementsByName('include/header.tmpl') || [];

    # Filter out any nodes which are not mt:Include's
    $nodes = [ grep { $_->nodeName eq 'include' } @$nodes ];

    # Sanity check: As in the place where I check for a problem and if one
    # exists, I forget the whole damn thing in order to save my sanity
    unless ( @$nodes == 1 ) {
        croak sprintf "%s: %s %s", __PACKAGE__ . '::edit_template_param',
          ( ( @$nodes > 1 ) ? 'More than one' : 'No' ),
          'header include found. Bailing out...';
    }
    ###l4p $logger->warn('NODE FOUND: INCLUDE HEADER');

    my $header_include = shift @$nodes;

    # Create the html_head setvarblock tag with append="1"
    $html_head = $tmpl->createElement( 'setvarblock',
                                       { name => 'html_head', append => 1 } );

    # Inject our code into the block
    $html_head->innerHTML($head_code);

    # Insert the setvarblock just before the header include
    $tmpl->insertBefore( $html_head, $header_include );
} ## end sub head_insertion

1;

__END__
