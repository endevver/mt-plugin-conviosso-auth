package REST::Client::Inheritable;

=head1 NAME

REST::Client::Inheritable - An inheritable version of REST::Client

=head1 SYNOPSIS

 use base qw( REST::Client::Inheritable );

=head1 DESCRIPTION

REST::Client::Inheritable provides the ability to more easily and consistently subclass REST::Client.

=cut

=head1 METHODS

=cut

use strict;
use warnings;
use version; $VERSION = qv('0.0.1');
use Carp ();

__PACKAGE__->mk_classdata( 'timeout' => 300 );
__PACKAGE__->mk_classdata( 'follow'  => join('/', __PACKAGE__, $VERSION) );
__PACKAGE__->mk_classdata( 'host' );
__PACKAGE__->mk_classdata( 'key' );
__PACKAGE__->mk_classdata( 'cert' );
__PACKAGE__->mk_classdata( 'ca' );
__PACKAGE__->mk_classdata( 'useragent' );
__PACKAGE__->mk_classdata( 'pkcs12' );
__PACKAGE__->mk_classdata( 'pkcs12password' );


sub init {
    my $self = shift;
}

# Make a set of accessors for each of a list of columns. We construct
# the method name by calling accessor_name_for() and mutator_name_for()
# with the normalized column name.

# mutator name will be the same as accessor name unless you override it.

# If both the accessor and mutator are to have the same method name,
# (which will always be true unless you override mutator_name_for), a
# read-write method is constructed for it. If they differ we create both
# a read-only accessor and a write-only mutator.

sub _mk_column_accessors {
    my $class = shift;
    foreach my $col (@_) {

        my $default_accessor = $col->accessor;

        my $acc = $class->accessor_name_for($col);
        my $mut = $class->mutator_name_for($col);

        my %method = ();

        if (
            ($acc    eq $mut)                # if they are the same
            or ($mut eq $default_accessor)
            ) {                              # or only the accessor was customized
            %method = ('_' => $acc);         # make the accessor the mutator too
            $col->accessor($acc);
            $col->mutator($acc);
            } else {
            %method = (
                _ro_ => $acc,
                _wo_ => $mut,
            );
            $col->accessor($acc);
            $col->mutator($mut);
        }

        foreach my $type (keys %method) {
            my $name     = $method{$type};
            my $acc_type = "make${type}accessor";
            my $accessor = $class->$acc_type($col->name_lc);
            $class->_make_method($_, $accessor) for ($name, "_${name}_accessor");
        }
    }
}

sub _make_method {
    my ($class, $name, $method) = @_;
    return if defined &{"$class\::$name"};
    $class->_carp("Column '$name' in $class clashes with built-in method")
        if Class::DBI->can($name)
        and not($name eq "id" and join(" ", $class->primary_columns) eq "id");
    no strict 'refs';
    *{"$class\::$name"} = $method;
    $class->_make_method(lc $name => $method);
}

sub accessor_name_for {
    my ($class, $column) = @_;
  if ($class->can('accessor_name')) { 
        warn "Use of 'accessor_name' is deprecated. Use 'accessor_name_for' instead\n";
        return $class->accessor_name($column) 
    }
    return $column->accessor;
}

sub mutator_name_for {
    my ($class, $column) = @_;
  if ($class->can('mutator_name')) { 
        warn "Use of 'mutator_name' is deprecated. Use 'mutator_name_for' instead\n";
        return $class->mutator_name($column) 
    }
    return $column->mutator;
}


my @attributes = qw(Host Key Cert Ca Timeout Follow Useragent Pkcs12 Pkcs12password);

use base qw( Class::Accessor Class::Data::Inheritable REST::Client );
Foo->follow_best_practice;
Foo->mk_accessors(qw(name role salary));


=head2 Construction and setup

=head3 new ( [%$config] )

Construct a new REST::Client. Takes an optional hash or hash reference or
config flags.  Each config flag also has get/set accessors of the form
getHost/setHost, getUseragent/setUseragent, etc.  These can be called on the
instantiated object to change or check values.

The config flags are:

=over 4

=item host

A default host that will be prepended to all requests.  Allows you to just
specify the path when making requests.

The default is undef - you must include the host in your requests.

=item timeout

A timeout in seconds for requests made with the client.  After the timeout the
client will return a 500.

The default is 5 minutes.

=item cert

The path to a X509 certificate file to be used for client authentication.

The default is to not use a certificate/key pair.

=item key

The path to a X509 key file to be used for client authentication.

The default is to not use a certificate/key pair.

=item ca

The path to a certificate authority file to be used to verify host
certificates.

The default is to not use a certificates authority.

=item pkcs12

The path to a PKCS12 certificate to be used for client authentication.

=item pkcs12password

The password for the PKCS12 certificate specified with 'pkcs12'.

=item follow

Boolean that determins whether REST::Client attempts to automatically follow
redirects/authentication.  

The default is false.

=item useragent

An L<LWP::UserAgent> object, ready to make http requests.  

REST::Client will provide a default for you if you do not set this.

=back

=cut

sub new {
    my $class = shift;
    my $config;

    $class->_buildAccessors();

    if(ref $_[0] eq 'HASH'){
        $config = shift;
    }elsif(scalar @_ && scalar @_ % 2 == 0){
        $config = {@_};
    }else{
        $config = {};
    }

    my $self = bless({}, $class);
    $self->{'_config'} = $config;

    $self->_buildUseragent();

    return $self;
}

=head3 addHeader ( $header_name, $value )

Add a custom header to any requests made by this client.

=cut

sub addHeader {
    my $self = shift;
    my $header = shift;
    my $value = shift;
    
    my $headers = $self->{'_headers'} || {};
    $headers->{$header} = $value;
    $self->{'_headers'} = $headers;
    return;
}

=head3 buildQuery ( [...] )

A convienience wrapper around URI::query_form for building query strings from a
variety of data structures. See L<URI>

Returns a scalar query string for use in URLs.

=cut

sub buildQuery {
    my $self = shift;

    my $uri = URI->new();
    $uri->query_form(@_);
    return $uri->as_string();
}



=head2 Request Methods

Each of these methods makes an HTTP request, sets the internal state of the
object, and returns the object.

They can be combined with the response methods, such as:

 print $client->GET('/search/?q=foobar')->responseContent();

=head3 GET ( $url, [%$headers] )

Preform an HTTP GET to the resource specified. Takes an optional hashref of custom request headers.

=cut

sub GET {
    my $self = shift;
    my $url = shift;
    my $headers = shift;
    return $self->request('GET', $url, undef, $headers);
}

=head3 PUT ($url, [$body_content, %$headers] )

Preform an HTTP PUT to the resource specified. Takes an optional body content and hashref of custom request headers.

=cut

sub PUT {
    my $self = shift;
    return $self->request('PUT', @_);
}

=head3 POST ( $url, [$body_content, %$headers] )

Preform an HTTP POST to the resource specified. Takes an optional body content and hashref of custom request headers.

=cut

sub POST {
    my $self = shift;
    return $self->request('POST', @_);
}

=head3 DELETE ( $url, [%$headers] )

Preform an HTTP DELETE to the resource specified. Takes an optional hashref of custom request headers.

=cut

sub DELETE {
    my $self = shift;
    my $url = shift;
    my $headers = shift;
    return $self->request('DELETE', $url, undef, $headers);
}

=head3 OPTIONS ( $url, [%$headers] )

Preform an HTTP OPTIONS to the resource specified. Takes an optional hashref of custom request headers.

=cut

sub OPTIONS {
    my $self = shift;
    my $url = shift;
    my $headers = shift;
    return $self->request('OPTIONS', $url, undef, $headers);
}

=head3 HEAD ( $url, [%$headers] )

Preform an HTTP HEAD to the resource specified. Takes an optional hashref of custom request headers.

=cut

sub HEAD {
    my $self = shift;
    my $url = shift;
    my $headers = shift;
    return $self->request('HEAD', $url, undef, $headers);
}

=head3 request ( $method, $url, [$body_content, %$headers] )

Issue a custom request, providing all possible values.

=cut

sub request {
    my $self = shift;
    my $method  = shift;
    my $url     = shift;
    my $content = shift;
    my $headers = shift;

    $self->{'_res'} = undef;
    $self->_buildUseragent();


    #error check
    croak "REST::Client exception: First argument to request must be one of GET, PUT, POST, DELETE, OPTIONS, HEAD" unless $method =~ /^(get|put|post|delete|options|head)$/i;
    croak "REST::Client exception: Must provide a url to $method" unless $url;
    croak "REST::Client exception: headers must be presented as a hashref" if $headers && ref $headers ne 'HASH';


    $url = $self->_prepareURL($url);

    #to ensure we use our desired SSL lib
    my $tmp_socket_ssl_version = $IO::Socket::SSL::VERSION;
    $IO::Socket::SSL::VERSION = undef;

    my $ua = $self->getUseragent();
    if(defined $self->getTimeout()){
        $ua->timeout($self->getTimeout);
    }else{
        $ua->timeout(300);
    }
    my $req = HTTP::Request->new( $method => $url );

    #build headers
    if($content){
        $req->content($content);
        $req->header('Content-Length', length($content));
    }else{
        $req->header('Content-Length', 0);
    }

    my $custom_headers = $self->{'_headers'} || {};
    for my $header (keys %$custom_headers){
        $req->header($header, $custom_headers->{$header});
    }

    for my $header (keys %$headers){
        $req->header($header, $headers->{$header});
    }


    #prime LWP with ssl certfile if we have values
    if($self->getCert){
        carp "REST::Client exception: Certs defined but not using https" unless $url =~ /^https/;
        croak "REST::Client exception: Cannot read cert and key file" unless -f $self->getCert && -f $self->getKey;

        $ENV{'HTTPS_CERT_FILE'} = $self->getCert;
        $ENV{'HTTPS_KEY_FILE'}  = $self->getKey; 
        if(my $ca = $self->getCa){
            croak "REST::Client exception: Cannot read CA file" unless -f $ca;
            $ENV{'HTTPS_CA_FILE'}  = $ca
        }
    }

    #prime LWP with PKCS12 certificate if we have one
    if($self->getPkcs12){
        carp "REST::Client exception: PKCS12 cert defined but not using https" unless $url =~ /^https/;
        croak "REST::Client exception: Cannot read PKCS12 cert" unless -f $self->getPkcs12;

        $ENV{HTTPS_PKCS12_FILE}     = $self->getPkcs12;
        if($self->getPkcs12password){
            $ENV{HTTPS_PKCS12_PASSWORD} = $self->getPkcs12password;
        }
    }

    my $res = $self->getFollow ? $ua->request($req) : $ua->simple_request($req);
    $IO::Socket::SSL::VERSION = $tmp_socket_ssl_version;

    $self->{_res} = $res;

    return $self;
}

=head2 Response Methods

Use these methods to gather information about the last requset
performed.

=head3 responseCode ()

Return the HTTP response code of the last request

=cut

sub responseCode {
    my $self = shift;
    return $self->{_res}->code;
}

=head3 responseContent ()

Return the response body content of the last request

=cut

sub responseContent {
    my $self = shift;
    return $self->{_res}->content;
}

=head3 responseHeaders()

Returns a list of HTTP header names from the last response

=cut

sub responseHeaders {
    my $self = shift;
    return $self->{_res}->headers()->header_field_names();
}



=head3 responseHeader ( $header )

Return a HTTP header from the last response

=cut

sub responseHeader {
    my $self = shift;
    my $header = shift;
    croak "REST::Client exception: no header provided to responseHeader" unless $header;
    return $self->{_res}->header($header);
}

=head3 responseXpath ()

A convienience wrapper that returns a L<XML::LibXML> xpath context for the body content.  Assumes the content is XML.

=cut

sub responseXpath {
    my $self = shift;

    require XML::LibXML;

    my $xml= XML::LibXML->new();
    $xml->load_ext_dtd(0);

    if($self->responseHeader('Content-type') =~ /html/){
        return XML::LibXML::XPathContext->new($xml->parse_html_string( $self->responseContent() ));
    }else{
        return XML::LibXML::XPathContext->new($xml->parse_string( $self->responseContent() ));
    }
}

# Private methods

sub _prepareURL {
    my $self = shift;
    my $url = shift;

    my $host = $self->getHost;
    if($host){
        $url = '/'.$url unless $url =~ /^\//;
        $url = $host . $url;
    }
    unless($url =~ /^\w+:\/\//){
        $url = ($self->getCert ? 'https://' : 'http://') . $url;
    }

    return $url;
}

sub _buildUseragent {
    my $self = shift;

    return if $self->getUseragent();

    my $ua = LWP::UserAgent->new;
    $ua->agent("REST::Client/$VERSION");
    $self->setUseragent($ua);

    return;
}

sub _buildAccessors {
    my $self = shift;

    return if $self->can('setHost');

    my @attributes = qw(Host Key Cert Ca Timeout Follow Useragent Pkcs12 Pkcs12password);

    for my $attribute (@attributes){
        my $set_method = "
        sub {
        my \$self = shift;
        \$self->{'_config'}{lc('$attribute')} = shift;
        return \$self->{'_config'}{lc('$attribute')};
        }";

        my $get_method = "
        sub {
        my \$self = shift;
        return \$self->{'_config'}{lc('$attribute')};
        }";


        {
            no strict 'refs';
            *{'REST::Client::set'.$attribute} = eval $set_method ;
            *{'REST::Client::get'.$attribute} = eval $get_method ;
        }

    }

    return;
}

1;


=head1 TODO

Caching, content-type negotiation, readable handles for body content.

=head1 AUTHOR

Miles Crawford, E<lt>mcrawfor@cpan.orgE<gt>

=head1 COPYRIGHT

Copyright 2008 - 2010 by Miles Crawford.

This program is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=cut
