<?php 

if (isset($_POST['action']) && $_POST['action'] == "disconnect") {
	
	apache_setenv("NETCONF_OP", "disconnect");
	apache_setenv("NETCONF_NSID", $_POST["nsid"]);
	virtual("/netconf/");
	
	echo "OK";
}

if (isset($_POST['action']) && $_POST['action'] == "login") {
	apache_setenv("NETCONF_OP", "connect");
	apache_setenv("NETCONF_HOST", "localhost");
	apache_setenv("NETCONF_PORT", "830");
	apache_setenv("NETCONF_USER", $_POST["login"]);
	apache_setenv("NETCONF_PASS", $_POST["password"]);
	virtual("/netconf/");
	
	echo "<html><body>";
	$out = apache_getenv("NETCONF_NSID");
	echo "NSID: ".$out;
	
	echo "<form method=\"post\" action=\"./index.php\" name=\"disconnect\">";
	echo "<input type=\"hidden\" name=\"action\" value=\"disconnect\">";
	echo "<input type=\"hidden\" name=\"nsid\" value=\"$out\">";
	echo "<input type=\"submit\" value=\"Disconnect\">";
	echo "</form>";
	echo "</body></html>";
	
	return ;
}

if (!isset($_POST['nsid'])) {
	/* no session related information known - redirect to the login page */
	header('Location: ./login.php');
	die();
}

?>
