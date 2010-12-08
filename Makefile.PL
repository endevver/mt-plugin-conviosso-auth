use ExtUtils::MakeMaker;

use YAML::Any qw(LoadFile);
my $file = "addons/ConvioSSOAuth.pack/config.yaml";
my $version = LoadFile($file)->{version} ||
    die "No version found in $file";

WriteMakefile(
    NAME            => 'ConvioSSOAuth',
    VERSION         => $version,
    DISTNAME        => 'ConvioSSOAuth',
);
