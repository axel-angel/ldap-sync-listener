#!/usr/bin/perl
# Copyright (c) 2014 Axel Angel <axel-oss@vneko.ch>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Net::LDAP::SyncDiffListener;

use strict;
use warnings;
use diagnostics; # FIXME: to remove

use YAML::Syck;
use Net::LDAP;
use Net::LDAP::Control::SyncRequest;
use Net::LDAP::Constant qw{LDAP_SYNC_REFRESH_AND_PERSIST};

our $VERSION = '0.1';

sub new($$) {
    my ($class, $statefile) = @_;

    my $obj = bless {}, $class;
    $obj->{statefile} = $statefile;
    $obj->{cookie} = "";
    $obj->{entries} = {};

    if (-e $obj->{statefile}) {
        my $state = LoadFile($statefile) if -e $obj->{statefile};
        $obj->{cookie} = $state->{cookie};
        $obj->{entries} = $state->{entries}
    }

    return $obj;
}

sub listen($$$$) {
    my ($self, $uri, $search, $callbacks) = @_;
    my $ldap = Net::LDAP->new($uri);

    my $sigint = sub {
        print "Clean exit\n";
        $self->save();
        $ldap->disconnect();
        sleep(1);
        exit 0;
    };

    $SIG{INT} = $sigint;

    print "Actual cookie: {$self->{cookie}}\n";

    my $req = Net::LDAP::Control::SyncRequest->new(
        mode => LDAP_SYNC_REFRESH_AND_PERSIST,
        critical => 'TRUE',
        cookie => $self->{cookie} // "",
    );

    my $mesg = $ldap->search(
        control  => [ $req ],
        callback => sub { $self->notify(@_) },
        %$search, # should define: base, scope, filter, attrs
    );
}

sub save {
    my ($self) = @_;

    print "writing state, cookie $self->{cookie}\n";
    DumpFile($self->{statefile}, {
        cookie => $self->{cookie},
        entries => $self->{entries},
    });
}

sub notify {
    my ($self, $message, $entry) = @_;
    my @controls = $message->control;

    print "Received something type(entry)=", ref $entry, "\n";
    print "  with ", (scalar @controls), " controls\n";


    if (not defined $entry) {
        warn "Ignoring undefined entry\n";
    }
    elsif ($entry->isa('Net::LDAP::Intermediate::SyncInfo')) {
        $self->{cookie} = $entry->{asn}{refreshDelete}{cookie};
        print "SyncInfo\n";
        $self->save();
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
}

1;
