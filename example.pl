#!/usr/bin/perl
# Copyright (c) 2014 Axel Angel <axel-oss@vneko.ch>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

use Net::LDAP::SyncDiffListener;

my %search = (
    base   => 'ou=Users,dc=ldap,dc=example,dc=com',
    scope  => 'sub',
    filter => "(objectClass=inetOrgPerson)",
    attrs  => ['*'],
);

my %callbacks = (
    add_entry => sub {
        my ($entry) = @_;
        print "add_entry: ", $entry->dn(), "\n";
    },
    del_entry => sub {
        my ($dn) = @_;
        print "del_entry: ", $dn, "\n";
    },
    add_attr_value => sub {
        my ($entry, $attr, $value) = @_;
        # not called in case of add_entry
        printf "add_attr_value %s %s %s\n", $entry->dn(), $attr, $value;
    },
    del_attr_value => sub {
        my ($entry, $attr, $value) = @_;
        # not called in case of del_entry
        printf "del_attr_value %s %s %s\n", $entry->dn(), $attr, $value;
    },
);

my $ldap = Net::LDAP::SyncDiffListener->new("ldaps://ldap.example.com");
$ldap->listen("state.yaml", \%search, \%callbacks);
