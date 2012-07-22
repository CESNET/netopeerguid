<?php 

if (isset($_POST['action']) && $_POST['action'] == "login") {
	apache_setenv("NETCONF_OP", "connect");
	apache_setenv("NETCONF_HOST", "localhost");
	apache_setenv("NETCONF_PORT", "830");
	apache_setenv("NETCONF_USER", $_POST["login"]);
	apache_setenv("NETCONF_PASS", $_POST["password"]);
	virtual("/netconf/");
	
	$out = apache_getenv("NETCONF_NSID");
	echo "NSID: ".$out;
	
	return ;
}

if (!isset($_POST['nsid'])) {
	/* no session related information known - redirect to the login page */
	header('Location: ./login.php');
	die();
}

?>
