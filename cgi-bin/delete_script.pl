#!/usr/bin/perl -wT
    
    use strict;
    use CGI;
    # process request for deleting a rules from web panel and add necessary line to "rules.dat".
    my $q = CGI->new();
    
    my $chain = $q->param('chain'); 
    my $priority = $q->param('priority'); #rule number.
    my $command;
    my $home_page; #
     
    my $time = 5; # time to "redirect, default is 5, it is set to "firewall-excuter.pl" delay time
     
    $command = $command . "-D " . $chain ." ". $priority."\n";#command like:iptables -D INPUT 2 
    my $data_file = 'data/rules.dat';
    open(FILE, ">>$data_file");
    print FILE $command;
    close (FILE);
    # finished writing to "rule.dat" file.
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
<title>deleting a rule - firewall web panel</title>
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
    print "<h6> request has been submitted successfully, you will be redirected in $time secounds...</h6>";
    print << 'EOHTML';
</div>
<br />
</body>
</html>

EOHTML
