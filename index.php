<?php
require("whoisClass.php");

$domain = $_GET['domain'];
$domain = strtolower(trim($domain));
$domain = preg_replace('/ /i', '', $domain);
$domain = preg_replace('/^http:\/\//i', '', $domain);
$domain = preg_replace('/^https:\/\//i', '', $domain);
$domain = explode('/', $domain);
$domain = trim($domain[0]);
if(substr_count($domain,".")==2){
$dotpos=strpos($domain,".");
$domtld=strtolower(substr($domain,$dotpos+1));
$whoisserver = $whoisservers[$domtld];
if(!$whoisserver) {if(strpos($domain,"www")===false){}else{$domain = preg_replace('/^www\./i', '', $domain);}}
}

function LookupDomain($domain){
global $whoisservers;
$whoisserver = "";

$dotpos=strpos($domain,".");
$domtld=strtolower(substr($domain,$dotpos+1));
$whoisserver = $whoisservers[$domtld];

if(!$whoisserver) {
return "Error: No appropriate Whois server found for <b>$domain</b> domain!";
}
//if($whoisserver == "whois.verisign-grs.com") $domain = "=".$domain; // whois.verisign-grs.com requires the equals sign ("=") or it returns any result containing the searched string.
$result = QueryWhoisServer($whoisserver, $domain);
if(!$result) {
return "Error: No results retrieved $domain !";
}

preg_match("/Whois Server: (.*)/", $result, $matches);
$secondary = $matches[1];
if($secondary) {
$result = QueryWhoisServer($secondary, $domain);
}
return  $result;
}

function QueryWhoisServer($whoisserver, $domain) {
$port = 43;
$timeout = 10;
$fp = @fsockopen($whoisserver, $port, $errno, $errstr, $timeout) or die("Socket Error " . $errno . " - " . $errstr);
fputs($fp, $domain . "\r\n");
$out = "";
while(!feof($fp)){
$out .= fgets($fp);
}
fclose($fp);
return $out;
}
?>
<!DOCTYPE html>
<html>
<head>
<title>WHOIS查询 - 最好用的IP,域名WHOIS查询系统</title>
<link rel="shortcut icon" href="favicon.ico">
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<meta name="keywords" content="whois,域名 whois,ip whois,Whois Search,whois查询,域名whois查询,ip whois查询">
<meta name="description" content="提供200多种域名后缀和IP的WHOIS信息查询服务，界面简洁，功能实用。">
<meta name="renderer" content="webkit">
<meta http-equiv="Cache-Control" content="no-siteapp"/>  
<meta name="baidu-site-verification" content="OUTe5BRcA2" />
<link rel="apple-touch-icon-precomposed" href="/app.png">
<link rel="stylesheet" type="text/css" href="style.css">
<script src="//lib.sinaapp.com/js/jquery/2.0.3/jquery-2.0.3.min.js"></script>
<script>
var _hmt = _hmt || [];
(function() {
  var hm = document.createElement("script");
  hm.src = "https://hm.baidu.com/hm.js?b3c483d1192ba042ed5ce2759f936ec7";
  var s = document.getElementsByTagName("script")[0]; 
  s.parentNode.insertBefore(hm, s);
})();
</script>
</head>
<body>
<div class="main">
<form action="<?php $_SERVER['PHP_SELF'];?>" id="form" class="form">
<h1><a href="https://222.ee">222.ee</a> - <a href="https://dan.com/zh-cn/buy-domain/222.ee">domain is for sale</a></h1>
<div class="search">
<input type="text" name="domain" id="domain" autocomplete="on" placeholder="Domain Name/IP">
<button id="submit" value="whois">WHOIS</button>
</div>
</form>
<h1><a target="_blank"  href="http://<?php if($_GET['domain'])echo $_GET['domain'];?>"><b><?php if($_GET['domain'])echo $_GET['domain'];?></b></a></h1>
<?php
if($domain) {
	if(preg_match("/^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/",$domain)){
$result = QueryWhoisServer("whois.apnic.net",$domain);
		echo "<pre>\n" . $result . "\n</pre>\n";
		// die("查询域名WHOIS格式, 比如. <i>222.ee</i>!");
	} else {
		$domain = IDN::decodeIDN($domain);
		$result = LookupDomain($domain);
		echo "<pre>\n" . $result . "\n</pre>\n";
	} 
}
?>
</div>
</body>
</html>
<?php
class IDN {
    // adapt bias for punycode algorithm
    private static function punyAdapt(
        $delta,
        $numpoints,
        $firsttime
    ) {
        $delta = $firsttime ? $delta / 700 : $delta / 2; 
        $delta += $delta / $numpoints;
        for ($k = 0; $delta > 455; $k += 36)
            $delta = intval($delta / 35);
        return $k + (36 * $delta) / ($delta + 38);
    }

    // translate character to punycode number
    private static function decodeDigit($cp) {
        $cp = strtolower($cp);
        if ($cp >= 'a' && $cp <= 'z')
            return ord($cp) - ord('a');
        elseif ($cp >= '0' && $cp <= '9')
            return ord($cp) - ord('0')+26;
    }

    // make utf8 string from unicode codepoint number
    private static function utf8($cp) {
        if ($cp < 128) return chr($cp);
        if ($cp < 2048) 
            return chr(192+($cp >> 6)).chr(128+($cp & 63));
        if ($cp < 65536) return 
            chr(224+($cp >> 12)).
            chr(128+(($cp >> 6) & 63)).
            chr(128+($cp & 63));
        if ($cp < 2097152) return 
            chr(240+($cp >> 18)).
            chr(128+(($cp >> 12) & 63)).
            chr(128+(($cp >> 6) & 63)).
            chr(128+($cp & 63));
        // it should never get here 
    }

    // main decoding function
    private static function decodePart($input) {
        if (substr($input,0,4) != "xn--") // prefix check...
            return $input;
        $input = substr($input,4); // discard prefix
        $a = explode("-",$input);
        if (count($a) > 1) {
            $input = str_split(array_pop($a));
            $output = str_split(implode("-",$a));
        } else {
            $output = array();
            $input = str_split($input);
        }
        $n = 128; $i = 0; $bias = 72; // init punycode vars
        while (!empty($input)) {
            $oldi = $i;
            $w = 1;
            for ($k = 36;;$k += 36) {
                $digit = IDN::decodeDigit(array_shift($input));
                $i += $digit * $w;
                if ($k <= $bias) $t = 1;
                elseif ($k >= $bias + 26) $t = 26;
                else $t = $k - $bias;
                if ($digit < $t) break;
                $w *= intval(36 - $t);
            }
            $bias = IDN::punyAdapt(
                $i-$oldi,
                count($output)+1,
                $oldi == 0
            );
            $n += intval($i / (count($output) + 1));
            $i %= count($output) + 1;
            array_splice($output,$i,0,array(IDN::utf8($n)));
            $i++;
        }
        return implode("",$output);
    }

    public static function decodeIDN($name) {
        // split it, parse it and put it back together
        return 
            implode(
                ".",
                array_map("IDN::decodePart",explode(".",$name))
            );
    }

}