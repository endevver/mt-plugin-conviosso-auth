package Net::Convio::OpenAPI;

use 5.008009;
use strict;
use warnings;
use base qw( Class::Accessor  Class::Data::Inheritable  Class::ErrorHandler );
use Data::Dumper;

# PRE-RELEASE VERSION see cpan-net-convio for eventual release version
use version 0.77; our $VERSION = $version = version->declare('v0.9.0');

use constant {
    API_VERSION => '1.0',  # Required but 1.0 is only valid value
    UA_STRING   => join('/', __PACKAGE__, $VERSION ),
};

__PACKAGE__->mk_accessors(qw(   
    host        short_name      api_key     _client     _request_params
 useragent servlet
));
# cons_id
# center_id       source            sub_source
# redirect        success_redirect  error_redirect
# login_name      login_password      useragent

__PACKAGE__->mk_classdata(                       'v' => API_VERSION );
__PACKAGE__->mk_classdata(                '_servlet' => 'client'    ); 
__PACKAGE__->mk_classdata(         'response_format' => 'json'      );
__PACKAGE__->mk_classdata(          'sign_redirects' => 'true'      );
__PACKAGE__->mk_classdata( 'suppress_response_codes' => 'false'     );

# use MT::Log::Log4perl qw( l4mtdump ); use Log::Log4perl qw( :resurrect ); our $logger;

sub client {
    my $self = shift;
    @_ and return $self->_client( @_ );
    unless ( $self->_client ) {
        my $ua;
        unless ( $self->useragent ) {
            require LWP::UserAgent;
            $self->useragent(
                $ua = LWP::UserAgent->new( agent => UA_STRING )   # Two fer'
            );
        }
        require REST::Client;
        $self->_client( REST::Client->new({ useragent => $ua })); # Slick
        eval {
            require Compress::Zlib;
            $self->_client->add_header('Accept-Encoding' => 'gzip');
        };
    }
    return $self->_client();
}

sub post_data {
    my $self    = shift;
    my %data    = @_;
    my $servlet = delete $data{servlet} || $self->servlet || $self->_servlet;
    my @classdata = qw(v   api_key         response_format
                           sign_redirects  suppress_response_codes);

    $data{$_} = $self->$_ foreach grep { ! defined $data{$_} } @classdata;
    
    $self->_request_params({ servlet => $servlet, %data });
    print STDERR 'Method params set: '.Dumper($self->_request_params);
return \%data;
    return $self->client->buildQuery( %data );
}

sub api_url {
    my $self = shift;
    my $api = $self->_request_params->{servlet} eq 'server' 
            ? 'SRConsAPI' : 'CRConsAPI';

    return sprintf( 'https://%s/%s/site/%s',
                    $self->host, $self->short_name, $api );
}

sub format_call {
    my $self     = shift;
    my $post     = $self->post_data( @_ );
    my $url      = $self->api_url();
    die $self->errstr unless $url and $post;
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();
    ###l4p $logger->debug('format_call: ', l4mtdump({
    ###l4p     url    => $url,
    ###l4p     curl   => 'curl -vvv -d '.join(' -d ', map { "$_=".$post->{$_}} keys %$post )." $url",
    ###l4p     params => $self->_request_params,
    ###l4p }));

    my @required = qw(method v api_key );
    push( @required, qw( login_name login_password ))
        if  $self->_request_params->{servlet} eq 'server'
        and ! $self->_request_params->{sso_auth_token};

    my @missing = grep { ! defined $self->_request_params
->{$_} } @required;
    return $self->error("Missing parameter(s): ".join(', ', @missing))
        if @missing;

    return ($url, $post);
}


sub make_call {
    my $self         = shift;
    my ($url, $post) = $self->format_call( @_ );
    die $self->errstr unless $url and $post;
    
    map { delete $post->{$_} }
        grep { ! defined $post->{$_} } keys %$post;

    $post       =~ s{^\?}{};
    my $client  = $self->client;
    my $ua      = $client->getUseragent();
    ###l4p $logger->debug('make_call: ', l4mtdump({ url => $url, post => $post}));

    my $response = $ua->post($url, $post);
    $client->{_res} = $response;
    # my $response = $client->POST( $url, $post );
    # return ( $client->responseCode() eq '200' )
    #      ? $client->responseContent()
    #      : $self->error( $client->responseContent() );
    unless ( $client->responseCode() eq '200' ) {
        return $self->error( $client->responseContent() );
    }
    return $client->responseContent();
}

1;

__END__

=head1 Net::Convio::OpenAPI


=head2 Common Parameters

Common Client and Server API Parameters

The following parameters are supported by all Convio Open APIs, both Client APIs and Server APIs:

method

    Required. The method to be invoked. Method names are case-sensitive, and by convention begin with a lower-case letter with camel-cased words.

    Type xsd:string

v

    Required. The version number for the API. Currently only version 1.0 is supported.

    Type xsd:string

api_key

    Required. An arbitrary value that must be passed when invoking the Convio Client and Server APIs. The value passed by the caller must match the value in the CONVIO_API_KEY site configuration parameter, which is unique for each Convio site. This value will be the same for all API methods. Note that this value is not considered secure and may be visible to end users.

    Type xsd:string

response_format

    Optional. The desired response format. Either "xml" or "json" may be specified. If no value is specified, then "xml" is the default.

    Type xsd:string

center_id

    Optional. The ID of a center (in a multi-center enabled site) to associate with the current session.

    Type xsd:nonNegativeInteger

source

    Optional. Text to associate with newly created constituent records to identify how or from where the record was added. This is recognized by all API methods even though most of them do not directly create constituent records. This is because the value is remembered in the visitor's current web browser session and used if they take any action, either via API call or browser interaction, that causes a new constituent record to be created.

    Type xsd:string

sub_source

    Optional. Further detail to save with the "source" information.

    Type xsd:string

error_redirect

    Optional. Specifies a URL redirect to send back to the browser after processing if an error has occurred.

    Type xsd:anyURI

redirect

    Optional. Specifies a URL redirect to send back to the browser after successful processing.

    Type xsd:anyURI

success_redirect

    Optional. Specifies a URL redirect to send back to the browser after successful processing.

    Type xsd:anyURI

sign_redirects

    Optional. Indicates that redirect URLs should include a digital signature. The digital signature consists of two additional parameters in the URL. The ts parameter will contain a timestamp associated with the completion of the API call. The sig parameter will contain an MD5 hash of the URL query string up to but not including the sig parameter, and the CONVIO_API_SECRET_KEY value.

    Type xsd:boolean

suppress_response_codes

    Optional. Specifies that all responses will be returned with an HTTP 200 OK status code - even errors. This parameter exists to accommodate Flash and JavaScript applications running in browsers

    that intercept all non-200 responses. If true, the client must determine error states by parsing the response body. Default is false.

    Type xsd:boolean


Common Server API Parameters
The following parameters are supported by all Convio Server APIs:

login_name

    Required for server API calls, invalid for client API calls. The user_name of the Convio administrative account that was created for API access. Note that this must be a special administrator account used just for API access.

    Type xsd:string

login_password


    Required for server API calls, invalid for client API calls. The password of the Convio administrative account that was created for API access. Note that this must be a special administrator account used just for API access.



    Type xsd:string

=cut
