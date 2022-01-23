#!/usr/bin/perl
#
# Use RFC2136 DNS updates with TSIG to set DNS challenge for certbot.
#
# Usage with certbot:
# --manual
# --preferred-challenges=dns
# --manual-auth-hook '/path/to/certbot-dns-update.pl -u'
# --manual-cleanup-hook '/path/to/certbot-dns-update.pl -d'
#
# https://github.com/WillCodeForCats
#

use strict;
use Net::DNS;
use Getopt::Std;

my %opts = ();
getopts ('ud', \%opts);

# config
my $dns_master = ""; #set dns update server here
my $sleep_time = 5;
my $tsig = Net::DNS::RR->new(
    name        => 'acmechallenge-key',
    type        => 'TSIG',
    algorithm   => '', #set algorithm here
    key         => '', #set shared secret here
);

# setup
my $domain = "_acme-challenge." . $ENV{'CERTBOT_DOMAIN'};
my $challenge = $ENV{'CERTBOT_VALIDATION'};
my $update = new Net::DNS::Update('rollernet.us', 'IN');
my $resolver = new Net::DNS::Resolver;

if (!defined($ENV{'CERTBOT_VALIDATION'})) {
    die("Error: CERTBOT_VALIDATION not set.");
}
if (!defined($ENV{'CERTBOT_DOMAIN'})) {
    die("Error: CERTBOT_DOMAIN not set.");
}

# send updates to master server
$resolver->nameservers($dns_master);

# add challenge record
if ($opts{'u'}) {
    $update->push( pre => nxdomain("$domain TXT") );
    $update->push( update => rr_add("$domain TXT $challenge") );
    $update->sign_tsig( $tsig );
}

# delete challenge record
elsif ($opts{'d'}) {
    $update->push( pre => yxdomain("$domain TXT") );
    $update->push( update => rr_del("$domain TXT") );
    $update->sign_tsig( $tsig );
}

# show usage help
else {
    print<<EOF;

Usage: certbot-dns-update -u|-d
    -u Update ACME Challenge
    -d Delete ACME Challenge

Data is passed in CERTBOT_DOMAIN and CERTBOT_VALIDATION environment variables.

EOF
exit(1);
}

# send update
my $reply = $resolver->send($update);

if ($reply) {
    if ( $reply->header->rcode eq 'NOERROR' ) {
        $reply->verify( $update ) || die $reply->verifyerr;
        sleep $sleep_time unless ($opts{'d'});
        print "Update succeeded: $domain $challenge\n";
        exit(0);
    }
    else {
        print 'Update failed: ', $reply->header->rcode, "\n";
        exit(1);
    }
}
else {
    print 'Update failed: ', $resolver->errorstring, "\n";
    exit(1);
}

