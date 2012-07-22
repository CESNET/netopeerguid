<html>
<body>

<center>
  <table cellpadding='2' cellspacing='0' border='1' id='login_table'>
  <tr><td align=center style="padding:2;padding-bottom:4">
    <b>Enter your login and password</b>
  </td></tr>
  <tr><td style="padding:5"><br>
	<form method="post" action="./index.php" name="login">
	  <input type="hidden" name="action" value="login">
      <input type="hidden" name="hide" value="">
	  <center>
	    <table>
		<tr><td>Login:</td><td><input type="text" name="login"></td></tr>
		<tr><td>Password:</td><td><input type="password" name="password"></td></tr>
		<tr><td>&nbsp;</td><td><input type="submit" value="Enter"></td></tr>
		</table>
      </center>
	</form>
  </td></tr>
  </table>
</center>

</body>
</html>
