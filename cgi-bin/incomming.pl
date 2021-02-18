#!/usr/bin/perl -wT

    use strict;
    use CGI;
    use IPTables::Parse;

my $q = CGI->new();
#prepare to use IPtable::Parse module...
my %opts = (
      'iptables' => '/sbin/iptables',
      'iptout'   => '/tmp/iptables.out',
      'ipterr'   => '/tmp/iptables.err',
      'ipt_file' => 'data/status.log', # iptables log file, always must be updated with current system state. firewall_executet.pl update it after executing each rule with iptables.
      'debug'    => 0,
      'verbose'  => 0
);

my $ipt_obj = new IPTables::Parse(%opts)
      or die "[*] Could not acquire IPTables::Parse object";
my $rules = $ipt_obj->chain_rules('filter', 'INPUT'); # select FILTER table and INPUT part of the status.log file.
my $size = @$rules; #size of the array, necessary for knowing rule_number & generating priority drop-down items
# html part just begun ///
print $q->header();
print << 'EOHTML';
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=windows-1252">
<title>Incomming traffic - firewall web panel</title>
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
<form class="jotform-form" action="script.pl" method="post" name="firewall" id="firewall" accept-charset="utf-8">
    <div class="form-all">
        <ul class="form-section">
        	<input type="hidden" name="chain" value="INPUT">
            <li id="cid_3" class="form-input-wide">
                <div class="form-header-group">
                    <h2 id="header_3" class="form-header">
                        Firewall
                    </h2>
                    <div id="subHeader_3" class="form-subHeader">
                        based on iptables
                    </div>
                </div>
            </li>
            <li id="cid_14" class="form-input-wide">
                <div class="form-header-group">
                    <h3 id="header_14" class="form-header">
                        Incomming:: New rule 
                    </h3>
                </div>
            </li>
			<li class="form-line form-line-column form-line form-line-column-clear" id="id_9">
                <label class="form-label-top" id="label_9" for="input_9"> action </label>
                <div id="cid_9" class="form-input-wide">
                    <select class="form-dropdown" style="width:80px" id="job" name="job">
                        <option selected="selected" value="DROP"> drop </option>
                        <option  value="ACCEPT"> accept </option>
			<option  value="REJECT"> reject </option>
                    </select>
                </div>
            </li>
			<li class="form-line form-line-column" id="id_5">
                <label class="form-label-top" id="label_5" for="input_5"> interface </label>
                <div id="cid_5" class="form-input-wide">
                    <input type="text" class="form-textbox" id="interface" name="in_interface" size="14" />
                </div>
            </li>
			<li class="form-line form-line-column form-line-column-clear" id="id_6">
                <label class="form-label-top" id="label_6" for="input_6"> protocol </label>
                <div id="cid_6" class="form-input-wide">
                    <select class="form-dropdown" style="width:80px" id="protocol" name="protocol">
                        <option selected="selected" value="tcp"> tcp </option>
                        <option value="udp"> udp </option>
                        <option value="icmp"> icmp </option>
                    </select>
                </div>
            </li>
            <li class="form-line form-line-column" id="id_2">
                <label class="form-label-top" id="source_ip_lbl" for="input_2"> source IP </label>
                <div id="cid_2" class="form-input-wide">
                    <input type="text" class="form-textbox" id="source" name="source_ip" size="16" />
                </div>
            </li>
			<li class="form-line form-line-column" id="id_4">
                <label class="form-label-top" id="label_4" for="input_4"> destination IP </label>
                <div id="cid_4" class="form-input-wide">
                    <input type="text" class="form-textbox" id="input_4" name="destination_ip" size="16" />
                </div>
            </li>
            <li class="form-line form-line-column form-line-column-clear" id="id_9">
                <label class="form-label-top" id="label_9" for="input_9"> priority </label>
                <div id="cid_9" class="form-input-wide">
                    <select class="form-dropdown" style="width:80px" id="priority" name="priority">
                        <option selected="selected" value="BOTTOM"> bottom </option>
                        <option  value="TOP"> top </option>

EOHTML
# generating numbers for priority drop-down menu according to available rules in the INPUT chain.
# getting rules number from index of the array in the module. (index of arrays starts with 0 not 1)
#
for (my $i = 0; $i < $size; ++$i) # this loop will generate 1 extra number, it's nice because user may choose "bottom" or that number :)
    {
     my $index_form_1 = $i+1; # adds 1 to array index. see ^^ for more details.
     print "<option  value=\"$index_form_1\"> $index_form_1 </option>";
    }
# an example of output:
# <option  value="1"> 1 </option>

#continuing html...
print<< 'EOHTML';
                    </select>
                </div>
            </li>
            <li class="form-line form-line-column" style="margin-left:207px;"  id="id_8">
                <label class="form-label-top"  id="label_8" for="input_8"> destination port </label>
                <div id="cid_8" class="form-input-wide">
                    <input type="text" class="form-textbox" id="destination_port" name="destination_port" size="16" maxlength="5" />
                </div>
			             
            <li class="form-line" id="id_11">
                <label class="form-label-top" id="label_11" for="input_11"> comment </label>
                <div id="cid_11" class="form-input-wide">
                    <input type="text" class="form-textbox" id="comment" name="comment" size="40" />
                </div>
            </li>
            <li class="form-line" id="id_1">
                <div id="cid_1" class="form-input-wide">
                    <div style="margin-left:156px" class="form-buttons-wrapper">
                        <button id="save" type="submit" class="form-submit-button">
                            apply
                        </button>
                        &nbsp; &nbsp; &nbsp;
                        <button id="reset" type="reset" class="form-submit-reset">
                            Clear
                        </button>
                    </div>
                </div>
            </li>
            <li style="display:none">
                Should be Empty:
                <input type="text" name="website" value="" />
            </li>
        </ul>
    </div>
    <input type="hidden" id="simple_spc" name="simple_spc" value="2701247054" />
    <script type="text/javascript">
        document.getElementById("si" + "mple" + "_spc").value = "2701247054-2701247054";
    </script>
    <input type="hidden" value="" id="input_13" name="q13_13" />
</form>
<div id="divider">
	<h3>available rules </h3>
	<table width="100%" id="log_table" cellpadding="1" cellspacing="2" >
<tr>
	<th>#</th>
	<th>source</th>
	<th>destination</th>
	<th>interface</th>
	<th>service</th>
	<th>policy</th>
	<th>remark</th>
	<th>actions</th>
   </tr>

EOHTML
# generating available rules table in the bottom of the page.
#     
    for (my $i = 0; $i < ($size-1);  ++$i) # array's element start from 0 to $size-1
    {
     my $rule_num = 1 + $i; #rule number = array's index +1;
     print "<tr><td>" . ($rule_num) . "</td>\n";
     print "<td>" . $rules->[$i]->{"src"} . "</td>\n";
     print "<td>" . $rules->[$i]->{"dst"} . "</td>\n";
     print "<td>" . $rules->[$i]->{"intf_in"} . "</td>\n";
     print "<td>" . $rules->[$i]->{"protocol"} ."(" . $rules->[$i]->{"d_port"} . ")</td>\n";
     print "<td>" . $rules->[$i]->{"target"} . "</td>\n";
     print "<td>" . $rules->[$i]->{"comment"} . "</td>\n";
     print qq{<td> edit  <form name="myform" class="jotform-form" action="delete_script.pl" method="POST">
<input type="hidden" name="priority" value=$rule_num>
<input type="hidden" name="chain" value="INPUT">
<input type="submit" value="delete" class="form-submit-button"></form></td></tr>\n};
    }
# output example:
#<tr>
#	<td>1</td>
#	<td>192.168.1.1/24</td>
#	<td>192.168.1.10</td>
#	<td>tcp(80)</td>
#	<td>REJECT</td>
#	<td>&nbsp;</td>
#	<td>edit delete</td>
#</tr>

print << 'EOHTML';
             </table>
	</div>
</div>
<br />
</body>
</html>

EOHTML
