#!/usr/bin/perl -wT
    
    use strict;
    use CGI;
    
    my $q = CGI->new();
    
    my $chain = $q->param('chain'); #input, output,forward
    my $source_ip = $q->param('source_ip'); 
    my $destination_ip = $q->param('destination_ip');
    my $protocol = $q->param('protocol');
    my $priority = $q->param('priority'); #rule number
    my $source_port = $q->param('source_port');
    my $destination_port = $q->param('destination_port');
    my $in_interface = $q->param('in_interface');
    my $out_interface = $q->param('out_interface');
    my $comment = $q->param('comment');
    my $job = $q->param('job'); #policy: ACCEPT, REJECT, DROP
    my $command;
    my $time = 5; # time to redirect, default is 5, it is set to "firewall-excuter.pl" delay time.
 
    if ($priority =~ /BOTTOM/){ #rule will append to table
       $command = "-A " . $chain;
    } elsif ($priority =~ /TOP/) {
       $command = "-I " . $chain;
    } else { # add rules to specified rule number possition.
       $command = "-I " . $chain . " " . $priority;
    }
    $command = $command . " -p " . $protocol; #protocol always has a value: tcp[by default], udp and icmp
    
    # specifying right option for interface, according to chain.
    if ($chain =~ /INPUT/ && $in_interface) {$command = $command . " -i " . $in_interface;} 
    elsif ($chain =~ /OUTPUT/ && $out_interface) { $command = $command . " -o " . $out_interface; }
    else { # FORWARD
                 if ($in_interface) {$command = $command . " -i " . $in_interface;} 
                 if ($out_interface) { $command = $command . " -o " . $out_interface; }
    }
    if ($source_ip) {
         $command = $command . " -s " . $source_ip;
    }
    if ($source_port) {
         $command = $command . " --sport " . $source_port;
    }
    if ($destination_ip) {
         $command = $command . " -d " . $destination_ip;
    }
    if ($destination_port) {
         $command = $command . " --dport " . $destination_port;
    }
    if ($comment) {
         $command = $command . " -m comment --comment \"" . $comment . "\"";
    }
    $command = $command . " -j " . $job . "\n"; #job always has a value, DROP[by default], REJECT, ACCEPT

    # writing new rule command option to the data file.
    my $data_file = 'data/rules.dat';
    open(FILE, ">>$data_file");
    print FILE $command;
    close (FILE);
    # finished writing to file, now redirecting to page.

    print $q->header();
    print << 'EOHTML'; 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=windows-1252">

EOHTML
    # redirect user to previous page using HTTP_REFERER in post header.
    print qq{<meta http-equiv="refresh" content="$time; url=$ENV{'HTTP_REFERER'}">};
    print << 'EOHTML';
<title>setting rule - firewall web panel</title>
</head>
<body topmargin="0" leftmargin="0" rightmargin="0" bottommargin="0" marginheight="0" marginwidth="0" bgcolor="#f6fbfc">
<script src="../js/jfrom.js" type="text/javascript"></script>
<script type="text/javascript">
   JotForm.init();
</script>
<link type="text/css" rel="stylesheet" href="../styles/form.css"/>
<link type="text/css" rel="stylesheet" href="../styles/jottheme.css" />
<style type="text/css">
    .form-label{
        width:150px !important;
    }
    .form-label-left{
        width:70px !important;
    }
    .form-line{
        padding:10px;
    }
    .form-label-right{
        width:150px !important;
    }
    .form-all{
        width:650px;
        background:url("../images/style1_bg.gif") repeat-x scroll center top rgb(255, 255, 255);
        color:#000080 !important;
        font-family:"Trebuchet MS";
        font-size:12px;
    }
	#container{
		display:block;
		width:650px;
		margin: 0 auto;
	}
	#divider{
		border-top: 1px solid #CCCCCC;
		background-color:#ffffff;
		padding-top:17px;
		
	}
	#divider h3{
		margin-left: 10px;
		margin-bottom: 2px;
		color:#000080;
		font-size:18px;
	}
	#log_table{
		width:100%;
		background-color:#e1f1f8;
		color:#000080;
		font-size:11px;
		
	}
	#log_table tr th {
		background-color:#b8e3f6;
	}
	#log_table tr td{
		text-align:center;
		border-bottom:dashed;
		border-bottom-width:thin;
		border-bottom-color:#000090;
	}
	
</style>
<div id="container">

EOHTML
    print "<h6> the new rule has been submitted successfully, you will be redirected in $time secounds...</h6>";
    print << 'EOHTML';
</div>
<br />
</body>
</html>

EOHTML
