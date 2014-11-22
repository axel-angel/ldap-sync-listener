#!/usr/bin/perl
# Copyright (c) 2014 Axel Angel <axel-oss@vneko.ch>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::SyncDiffListener;

use strict;
use warnings;
use diagnostics; # FIXME: to remove

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(ldap_listen);

use YAML::Syck;
use Net::LDAP;
use Net::LDAP::Control::SyncRequest;
use Net::LDAP::Constant qw{LDAP_SYNC_REFRESH_AND_PERSIST};

sub ldap_listen($$$$) {
    my ($uri, $statefile, $search, $callbacks) = @_;

    my $ldap = Net::LDAP->new($uri);

    my $s = {};
    $s = LoadFile($statefile) if -e $statefile;

    my $sigint = sub {
        print "Clean exit\n";
        $ldap->disconnect();
        sleep(1);
        exit 0;
    };

    $SIG{INT} = $sigint;

    print "Actual cookie: {$s->{cookie}}\n" if defined $s->{cookie};

    my $notify = sub {
        my ($message, $entry) = @_;
        my @controls = $message->control;

        print "Received something type(entry)=", ref $entry, "\n";
        print "  with ", (scalar @controls), " controls\n";


        if (not defined $entry) {
            print "Skipping undefined entry\n";
        }
        elsif ($entry->isa('Net::LDAP::Intermediate::SyncInfo')) {
            $s->{cookie} = $entry->{asn}{refreshDelete}{cookie};
            print "SyncInfo\n";
            if (defined $s->{cookie}) {
                print "  write cookie: $s->{cookie}\n";
                DumpFile($statefile, $s);
            }
            else {
                print "  no new cookie\n";
            }
        }
        elsif ($entry->isa('Net::LDAP::Entry')) {
            print "Regular entry\n";
        }

        print "  entry={\n", Dump($entry), "\n}\n" if $entry;

        foreach my $control (@controls) {
            print "*"x80, "\n";

            print "- Control type ", ref $control, "\n";
            if ($control->isa('Net::LDAP::Control::SyncState')) {
                print "  Received Sync State Control\n";
                print "  entry dns: ", $entry->dn(), "\n";
                print "  state: ", $control->state, "\n";
                print "  entryUUID: ", $control->entryUUID, "\n";
            } elsif ($control->isa('Net::LDAP::Control::SyncDone')) {
                print "  Received Sync Done Control\n";
                print "  refreshDeletes: ", $control->refreshDeletes, "\n";
            }
            else {
                warn "Received something else: ", ref $control, "\n";
            }
        }
        print "="x80, "\n";
    };

    my $req = Net::LDAP::Control::SyncRequest->new(
        mode => LDAP_SYNC_REFRESH_AND_PERSIST,
        critical => 'TRUE',
        cookie => $s->{cookie} // "",
    );


    my $mesg = $ldap->search(
        control  => [ $req ],
        callback => $notify,
        %$search, # should define: base, scope, filter, attrs
    );
}

1;
