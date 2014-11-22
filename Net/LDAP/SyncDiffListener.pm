#!/usr/bin/perl
# Copyright (c) 2014 Axel Angel <axel-oss@vneko.ch>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.
#
# LDAP Sync spec: http://tools.ietf.org/html/rfc4533

package Net::LDAP::SyncDiffListener;

use strict;
use warnings;
use diagnostics; # FIXME: to remove

use YAML::Syck;
use Net::LDAP;
use Net::LDAP::Control::SyncRequest;
use Net::LDAP::Constant qw{LDAP_SYNC_REFRESH_AND_PERSIST};

our $VERSION = '0.1';

sub new($$$) {
    my ($class, $statefile, $callbacks) = @_;

    my $obj = bless {}, $class;
    $obj->{statefile} = $statefile;
    $obj->{callbacks} = $callbacks;
    $obj->{cookie} = "";
    $obj->{entries} = {};

    if (-e $obj->{statefile}) {
        my $state = LoadFile($statefile) if -e $obj->{statefile};
        $obj->{cookie} = $state->{cookie};
        $obj->{entries} = $state->{entries}
    }

    return $obj;
}

sub listen($$$) {
    my ($self, $uri, $search) = @_;
    my $ldap = Net::LDAP->new($uri);

    my $sigint = sub {
        print "Clean exit\n";
        $self->save();
        $ldap->disconnect();
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

    if (not defined $entry) {
        warn "Ignoring undefined entry\n";
    }
    elsif ($entry->isa('Net::LDAP::Intermediate::SyncInfo')) {
        $self->handle_syncinfo($message, $entry);
    }
    elsif ($entry->isa('Net::LDAP::Entry')) {
        $self->handle_entry($message, $entry);
    }
    else {
        $self->handle_other($message, $entry);
    }

}

sub handle_syncinfo($$$) {
    my ($self, $message, $entry) = @_;
    my @controls = $message->control;
    print "SyncInfo\n";

    warn "Unexpected SyncInfo with controls, ignored" if @controls;

    my $cookie = $entry->{asn}{refreshDelete}{cookie}
              || $entry->{asn}{refreshPresent}{cookie};

    if (defined $cookie) {
        print "Received new cookie: $cookie\n";
        $self->{cookie} = $cookie;
        $self->save();
    }
    else {
        print "\tno cookie but: ", Dump($entry), "\n";
    }
}

sub handle_entry($$$) {
    my ($self, $message, $entry) = @_;

    my @controls = $message->control;
    my $control_count = scalar @controls;
    if ($control_count != 1) {
        warn "Entry with ", $control_count," controls, skipping";
        return;
    }

    print "entry={\n", Dump($entry), "\n}\n" if $entry;

    my $control = $controls[0];
    if ($control->isa('Net::LDAP::Control::SyncState')) {
        my $state = $control->state;
        my $dn = $entry->dn();

        printf "Sync State Control: dispatching: %s (state=%i)\n", $dn, $state;

        if ($state == 0) { # present
            warn "Entry control says present, nothing to do";
        }
        elsif ($state == 1) { # add
            if (defined $self->{entries}{$dn}) {
                warn "Entry control says it's new when it's not";
                $self->handle_entry_changed($entry);
            }
            else {
                $self->{callbacks}{add_entry}($entry);
                my %attrs = $self->hash_entry($entry);
                $self->{entries}{$dn} = \%attrs;
            }
        }
        elsif ($state == 2) { # modify
            $self->handle_entry_changed($entry);
        }
        elsif ($state == 3) { # delete
            $self->{callbacks}{del_entry}($entry);
            delete $self->{entries}{$dn};
        }
        else {
            warn "Entry control unexpected state, ", $state, " ignoring";
        }
    } elsif ($control->isa('Net::LDAP::Control::SyncDone')) {
        print "  Received Sync Done Control\n";
        print "  refreshDeletes: ", $control->refreshDeletes, "\n";
    }
    else {
        warn "Entry with unexpected control type: ", ref $control;
    }
}

sub handle_entry_changed($$) {
    my ($self, $entry) = @_;
    my $dn = $entry->dn;
    print "Entry changed ", $dn, "\n";

    # TODO: handle diff here

    my %attrs = $self->hash_entry($entry);
    $self->{entries}{$dn} = \%attrs;
}

sub handle_other($$$) {
    my ($self, $message, $entry) = @_;
    warn "Unexpected entry type: ", ref $entry;
}

sub hash_entry($$) {
    my ($self, $entry) = @_;
    my %attrs = ();
    foreach my $key ($entry->attributes) {
        $attrs{$key} = $entry->get_value($key, asref => 1);
    }
    return %attrs;
}

1;
