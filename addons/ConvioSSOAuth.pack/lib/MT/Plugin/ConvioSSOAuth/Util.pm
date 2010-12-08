package MT::Plugin::ConvioSSOAuth::Util;

use strict;
use warnings;
use base 'Exporter';
our @EXPORT_OK = qw( is_token_valid VALID INVALID MALFORMED );

use Net::Convio::OpenAPI;
use MT::Plugin::ConvioSSOAuth;
use MT::Log::Log4perl qw( l4mtdump );
use Log::Log4perl qw( :resurrect );
our $logger;

sub VALID ()     {1}
sub INVALID ()   {-1}
sub MALFORMED () {0}

sub convio_instance {
    my $app = MT->instance;
    my $cfg = $app->config();
    ###l4p $logger ||= MT::Log::Log4perl->new(); $logger->trace();
    my $convio = Net::Convio::OpenAPI->new( {
           host       => $cfg->get('ConvioSSOAuthHost'),
           short_name => $cfg->get('ConvioSSOClientID'),
           api_key    => $cfg->get('ConvioSSOAPIKey'),
           v          => $cfg->get('ConvioSSOAPIVersion'),

           # useragent      => $app->new_ua({ agent => USER_AGENT }),
           # ConvioSSOErrorRedirectBase:
           # ConvioSSOSuccessRedirectBase:
        }
    );
    ###l4p $logger->info('Convio: ', l4mtdump($convio));
    return $convio;
}

1;
