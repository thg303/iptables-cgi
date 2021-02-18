#!/usr/bin/perl -w

$cgi_path = '';#'/home/uecadmin/public_html/cgi-bin/';
$log_file = $cgi_path . 'data/report.log';
$data_file = $cgi_path . 'data/rules.dat';
$iptables = '/sbin/iptables';
$iptables_log = $cgi_path . 'data/status.log';

# chk for ownership and permissions of "data/"
open(FILE, ">$data_file"); #cleaning the rules.dat file.
print FILE ""; 
close(FILE);
$wuid = getpwnam("www-data"); #get uid of www-data
open(FILE, "$data_file");
$mode = (stat(FILE))[2]; #permission of the file
printf "$data_file permission is %04o\n", ($mode & 07777);
$file_uid = (stat(FILE))[4]; # get uid of the file's owner
$file_guid = (stat(FILE))[5]; # get "group uid" of the file's owner
close(FILE);

if (($file_uid != $wuid) || (($mode & 07777) != 0644)) { #  chk rules.dat for ownership and permissions
	print "warning: \"data/rules.dat\" doesn't have correct ownership or necessary permission.\nsetting new owner/permission...";
	chown $wuid, $file_guid, $data_file; # change 'rules.dat' ownership to apache's user
	chmod 0644 , $data_file; # 0644, is write/read permission for www-data and read for others.
}

#check for status.log file existence and sufficient permission
if (!-e "$iptables_log") {
 print "$iptables_log does not exist or has irrelevent permission\n generating the file...";
 $rules_updated='true';
}


while (1) {
@applyable_rules = ("");
@error_warnings = (""); #used for "report.log"
open(FILE, "$data_file");
@lines = <FILE>; # read lines and put them in array
close(FILE);
print @lines;  # print ALL lines.
foreach $single_line (@lines) #parse every line
{
	if ($single_line =~ /^[-]/) # iptables command options must start with "-"
	{
		push(@applyable_rules, $single_line); #  command options stores in array
		$rules_updated = 'true'; # 
	} else { # ignore every line which doesn't start with "-" and log it in report.log
		push(@error_warnings, "!: ". current_time() ." :(unexecuted) iptalbes $single_line"); # unexecutable line stores in array	
	}
}

{
	local $ENV{"PATH"}="/sbin:/usr/bin"; # $ENV{"PATH"} must be set for security reasons.
	foreach $single_rule (@applyable_rules) # running iptables command for all executable rules.
	{
		if ($single_rule ne ""){ # if there's no rule, nothing will be executed.		
		 print "$iptables $single_rule\n";
    		 $result = system("$iptables $single_rule");
    		 if ($result != 0) { # if there's an error while running the command>
        	  print "X: ($result) iptables $single_rule\n";
		  push (@error_warnings, "X: ". current_time() ." :($result) iptables $single_rule");
    		 }		
		}
	}
}
open(FILE, ">$data_file"); #cleaning the rules.dat file.
print FILE ""; 
close(FILE);
open(FILE, ">>$log_file"); # create "report.log" in "data/" 
print FILE @error_warnings;
close (FILE);
if ($rules_updated) { # update status.log file to match iptables' current state.
  local $ENV{"PATH"}="/sbin:/usr/bin";
  $iptables = '/sbin/iptables';
  $single_rule = '-nL -v'; # parameter to generate log from iptalbes.
  $result = system("$iptables $single_rule > $iptables_log");
  $rules_updated = '';
}
sleep(5); # pause time to re-executing the script
}

# this function generates current time based on local machine's time. 
sub current_time
{
  @months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
  @weekDays = qw(Sun Mon Tue Wed Thu Fri Sat Sun);
  my ($second, $minute, $hour, $dayOfMonth, $month, $yearOffset, $dayOfWeek, $dayOfYear,$daylightSavings) = localtime();
  $year = 1900 + $yearOffset;
  $theTime = "$hour:$minute:$second, $weekDays[$dayOfWeek] $months[$month] $dayOfMonth, $year";
  return $theTime; 
}
