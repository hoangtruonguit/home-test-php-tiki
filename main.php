<?php

require_once('PasswordManager.php');

echo " TIKI HOME TEST USING PHP \n";
echo "*******========================================================================********\n";
		
$passwordManager = new PasswordManager();
$passwordManager->run();

