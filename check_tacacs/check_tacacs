#!/usr/bin/perl
#
#    check_tacacs nagios plugin
#    Copyright (C) 2012 Nicolas Limage
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
use strict;
use warnings;
#use lib '/usr/lib/nagios/plugins/lib';
use Nagios::Plugin;
use Authen::TacacsPlus;
use Time::HiRes qw(gettimeofday tv_interval);

my $np = Nagios::Plugin->new(
	shortname => 'TACACS',
	usage => "usage: check_tacacs -H <host_address> [-p <port>] -k <key> -U <username> -P <password>\n   use --help for more info",
	plugin => 'TACACS',
	version => '1.1'
);

$np->add_arg(
	spec => 'hostname|H=s',
	help => "-H, --hostname=<host_address>\n   Hostname to check",
	required => 1,
);

$np->add_arg(
	spec => 'port|p=i',
	help => "-p, --port=<port>\n   Tacacs server port (default: 49)",
	default => 49,
);

$np->add_arg(
	spec => 'key|k=s',
	help => "-k, --key=<key>\n   Tacacs server key",
	required => 1,
);

$np->add_arg(
	spec => 'username|U=s',
	help => "-U, --username=<username>\n   username for authentication",
);

$np->add_arg(
	spec => 'password|P=s',
	help => "-P, --password=<password>\n   password for authentication",
);

$np->add_arg(
	spec => 'warning|w=s',
	help => '-w, --warning=INTEGER:INTEGER .  See '
		. 'http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT '
		. 'for the threshold format. ',
);

$np->add_arg(
	spec => 'critical|c=s',
	help => '-c, --critical=INTEGER:INTEGER .  See '
		. 'http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT '
		. 'for the threshold format. ',
);

$np->getopts();

# safety net - should not trigger
alarm ($np->opts->timeout + 5);

my $tac = new Authen::TacacsPlus(
	Host => $np->opts->hostname,
	Key => $np->opts->key,
	Port => $np->opts->port,
	Timeout => $np->opts->timeout
);

if (!$tac)
{
	$np->nagios_exit(CRITICAL, "Connection Error: " . Authen::TacacsPlus::errmsg());
}

my $t0 = [gettimeofday];

if ($tac->authen($np->opts->username, $np->opts->password))
{
	my $elapsed = tv_interval($t0);

	$np->set_thresholds(
		warning => $np->opts->warning,
		critical => $np->opts->critical
	);

	my $code = $np->check_threshold($elapsed);

	$np->add_perfdata(
		label => "response time",
		value => $elapsed,
		uom => 's',
		min => 0,
		threshold => $np->threshold(),
	);

	$tac->close();
	$np->nagios_exit($code, sprintf("Authentication Succeeded in %ss", $elapsed));
}
else
{
	$tac->close();
	$np->nagios_exit(CRITICAL, 'Authentication Error: ' . Authen::TacacsPlus::errmsg());
}
