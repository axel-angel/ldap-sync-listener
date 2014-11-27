#!/usr/bin/perl
# Copyright (c) 2014 Axel Angel <axel-oss@vneko.ch>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.
#
# requires: libnet-ldap-perl libyaml-syck-perl libarray-diff-perl
#
# LDAP Sync spec: http://tools.ietf.org/html/rfc4533

package Net::LDAP::SyncDiffListener;
use parent 'Net::LDAP';

use strict;
use warnings;

use YAML::Syck;
use Net::LDAP;
use Net::LDAP::Control::SyncRequest;
use Net::LDAP::Constant qw{LDAP_SYNC_REFRESH_AND_PERSIST};
use Array::Diff;

our $VERSION = '0.1';
use constant DEBUG => 0;

sub new {
    my $class = shift;
    my $obj = $class->SUPER::new(@_);

    $obj->{statefile} = undef;
    $obj->{callbacks} = {};
    $obj->{cookie} = "";
    $obj->{entries} = {};

    return $obj;
}

sub listen($$$$) {
    my ($self, $statefile, $search, $callbacks) = @_;

    $self->{statefile} = $statefile;
    $self->{callbacks} = $callbacks;

    if (-e $self->{statefile}) {
        my $state = LoadFile($statefile) if -e $self->{statefile};
        $self->{cookie} = $state->{cookie};
        $self->{entries} = $state->{entries}
    }

    my $sigint = sub {
        print "Clean exit\n" if DEBUG;
        $self->save();
        $self->disconnect();
    };

    $SIG{INT} = $sigint;

    print "Actual cookie: {$self->{cookie}}\n" if DEBUG;

    my $req = Net::LDAP::Control::SyncRequest->new(
        mode => LDAP_SYNC_REFRESH_AND_PERSIST,
        critical => 'TRUE',
        cookie => $self->{cookie} // "",
    );

    my $mesg = $self->search(
        control  => [ $req ],
        callback => sub { $self->notify(@_) },
        %$search, # should define: base, scope, filter, attrs
    );
}

sub save() {
    my ($self) = @_;

    print "writing state, cookie $self->{cookie}\n" if DEBUG;
    DumpFile($self->{statefile}, {
        cookie => $self->{cookie},
        entries => $self->{entries},
    });
}

sub notify($$$) {
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
    print "SyncInfo\n" if DEBUG;

    warn "Unexpected SyncInfo with controls, ignored" if @controls;


    # check and take the cookie
    my $cookie = $entry->{asn}{refreshDelete}{cookie}
              || $entry->{asn}{refreshPresent}{cookie};

    if (defined $cookie) {
        print "Received new cookie: $cookie\n" if DEBUG;
        $self->{cookie} = $cookie;
        $self->save();
    }

    # check and handle refreshOnly deletions
    my $syncidset = $entry->{asn}{syncIdSet};
    if ($syncidset and $syncidset->{syncUUIDs}) {
        my %uuids = map { unpack('H*', $_) => 1 } @{$syncidset->{syncUUIDs}};
        my $islistdel = $syncidset->{refreshDeletes};

        foreach my $uuid (keys %{$self->{entries}}) {
            my $isdel = $islistdel == defined $uuids{$uuid};

            if ($isdel) {
                my $dn = $self->{entries}{$uuid}{dn};
                $self->{callbacks}{del_entry}($dn);
                delete $self->{entries}{$uuid};
            }
        }
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

    print "entry={\n", Dump($entry), "\n}\n" if $entry and DEBUG;

    my $control = $controls[0];
    if ($control->isa('Net::LDAP::Control::SyncState')) {
        my $state = $control->state;
        my $dn = $entry->dn();
        my $uuid = unpack('H*', $control->entryUUID);

        printf "Sync State Control: %s (uuid=%s, state=%i)\n",
            $dn, $uuid, $state if DEBUG;

        if ($state == 0) { # present
            warn "Entry control says present, nothing to do";
        }
        elsif ($state == 1) { # add
            if (defined $self->{entries}{$uuid}) {
                warn "Entry control says it's new when it's not";
                $self->handle_entry_changed($uuid, $entry);
            }
            else {
                $self->{callbacks}{add_entry}($entry);
                my %attrs = $self->hash_entry($entry);
                $self->{entries}{$uuid} = {
                    dn => $entry->dn,
                    attrs => \%attrs
                };
            }
        }
        elsif ($state == 2) { # modify
            $self->handle_entry_changed($uuid, $entry);
        }
        elsif ($state == 3) { # delete
            $self->{callbacks}{del_entry}($entry->dn);
            delete $self->{entries}{$uuid};
        }
        else {
            warn "Entry control unexpected state, ", $state, " ignoring";
        }
    }
    else {
        warn "Entry with unexpected control type: ", ref $control;
    }
}

sub handle_entry_changed($$) {
    my ($self, $uuid, $entry) = @_;
    my $dn = $entry->dn;
    print "Entry changed ", $dn, "\n" if DEBUG;

    my %attrs_old = %{$self->{entries}{$uuid}{attrs}};
    my %attrs_new = $self->hash_entry($entry);

    my @keys_old = keys %attrs_old;
    my @keys_new = keys %attrs_new;

    # add/del of values for attributes
    my @keys_all = keys(%{{ map { $_ => 1 } (@keys_old, @keys_new) }});
    foreach my $key (@keys_all) {
        my $vals_old = $attrs_old{$key} // [];
        my $vals_new = $attrs_new{$key} // [];

        my $diff = Array::Diff->diff($vals_old, $vals_new);
        foreach (@{$diff->deleted}) {
            $self->{callbacks}{del_attr_value}($entry, $key, $_);
        }
        foreach (@{$diff->added}) {
            $self->{callbacks}{add_attr_value}($entry, $key, $_);
        }
    }

    $self->{entries}{$uuid} = {
        dn => $entry->dn,
        attrs => \%attrs_new,
    };
}

sub handle_other($$$) {
    my ($self, $message, $entry) = @_;
    warn "Unexpected entry type: ", ref $entry;
}

sub hash_entry($$) {
    my ($self, $entry) = @_;
    my %attrs = ();
    foreach my $key ($entry->attributes) {
        my $values = $entry->get_value($key, asref => 1);
        $attrs{$key} = ref $values ? $values : [ $values ];
    }
    return %attrs;
}

1;
