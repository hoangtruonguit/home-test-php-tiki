<?php

class PasswordManager
{
	const NEW_USER_KEY = 'A';
	const VALIDATE_PASSWORD_KEY = 'B';
	const LOGIN_KEY = 'C';
	const CHANGE_PASSWORD_KEY = 'D';
	const STORAGE_FILE_NAME = __DIR__ . '/password.txt';

	private $username;
	private $password;

	public function setUsername(string $username)
	{
		$this->username = $username;
	}

	public function getUsername()
	{
		return $this->username;
	}

	public function setPassword(string $password)
	{
		$this->password = $password;
	}

	public function getPassword()
	{
		return $this->password;
	}

	public function run()
	{
        echo "Please select one of below options. Press Cmd/Ctrl + C to exit\n";
        echo "A. New User\n";
        echo "B. Validate Password\n";
        echo "C. Login \n";
        echo "D. Change Password\n";
        echo "Your choice : ";

        $handle = fopen ("php://stdin","r");
        $line = fgets($handle);
        fclose($handle);
        switch(trim(strtoupper($line))) {
            case self::NEW_USER_KEY:
                $this->createUserOpt();
                break;
            case self::VALIDATE_PASSWORD_KEY:
                $this->validatePasswordOpt();
                break;
            case self::LOGIN_KEY:
                $this->login();
                break;
            case self::CHANGE_PASSWORD_KEY:
                $this->changePassWord();
                break;
            default:
                echo "Invalid options \n";
                break;
        }

	}
	
	public function createUserOpt()
	{
        echo "========================Create User=========================\n";
        try {
			$user = false;

			$username = $this->getUsernameFromInput();
			$password = $this->getPasswordFromInput();

			if(!empty($username) && !empty($password)) {
				$user = $this->createUser();
			}

			if($user) {
				echo "Create new user `$username` success.\n";
			}
		} catch(Exception $e) {
			echo 'System errors: ' . $e->getMessage();
		}
		exit();
	}

	public function login()
	{
        echo "========================LOGIN MODE=========================\n";
        try {
			$validPassword = false;

			$username = $this->getUsernameFromInput(false);
			$password = $this->getPasswordFromInput();
			
			if(!empty($username) && !empty($password)) {
				$user = $this->findUserByUsername($username);
				$validPassword = $this->verifyPassword($user['password']);
			}

			echo $validPassword ? "Login successfully !\n" : " Login fail!\n";
		} catch(Exception $e) {
			echo 'Some system errors: ' . $e->getMessage();
		}
		exit();
	}

    /**
     * @throws Exception
     */
    public function validatePasswordOpt()
    {
        echo "========================Validate Password mode=========================\n";

        try {
            $password = $this->getPasswordFromInput();
            $isValidPassword = $this->validatePassword($password);

            echo !$isValidPassword ? "Wrong password.\n" : "Correct password.\n";
        } catch (Exception $e) {
            echo 'Some system errors: ' . $e->getMessage();

        }

    }

    protected function changePassWord()
    {
        echo "========================Change Password=========================\n";

        try {
            $username = $this->getUsernameFromInput(false);
            $password = $this->getPasswordFromInput('Enter current password:');

            if(!empty($username) && !empty($password)) {
                $user = $this->findUserByUsername($username);
                $validPassword = $this->verifyPassword($user['password']);
                if ($validPassword){
                    $newPassWord = $this->getPasswordFromInput('Enter new password:');
                    $hashPassword = $this->encrypt($newPassWord);
                    $content = file_get_contents(self::STORAGE_FILE_NAME);
                    $newContent = str_replace($user['username']."-".$user['password'], $user['username']."-".$hashPassword, $content);

                    $isChange = file_put_contents(self::STORAGE_FILE_NAME, $newContent);

                    echo $isChange ? "Change Password successfully\n" : "Change Password failure\n";
                } else {
                    echo 'Incorect Password! Try again';
                }
            }

        } catch(Exception $e) {
            echo 'Some system errors: ' . $e->getMessage();
        }
        exit();

    }


    /**
     * @param string $password
     * @return bool
     * @throws Exception
     */
    public function setNewPassword(string $password)
	{
		$isValidPassword = $this->validatePassword($password);
		if(!$isValidPassword) {
            return false;
		}
        $hash = $this->encrypt($password);
        $this->setPassword($hash);

        return true;
	}

    /**
     * @param string $password
     * @return bool
     * @throws Exception
     */
    public function validatePassword(string $password)
	{
		if(empty($password)) {
			throw new Exception('**The password cannot be empty.**');
		} elseif(!preg_match("/^(?=.*[a-z])(?=.*[A-Z]).+$/", $password)) {
			throw new Exception('**The password must contain at least one uppercase and at least one lowercase letter.**');
		} elseif(!preg_match("/^(?=.*\d)(?=.*(_|[^\w])).+$/", $password)) {
			throw new Exception('**The password must have at least one digit and symbol.**');
		} elseif(!preg_match("/^\S+$/", $password)) {
			throw new Exception('**The password must not contain any whitespace.**');
		} elseif(!preg_match("/^.{6,}$/", $password)) {
			throw new Exception('**The password must be at least 6 characters long.**');
		}

		return true;
	}

    /**
     * @param bool $isNew
     * @return string|null
     */
    protected function getUsernameFromInput($isNew = true)
	{

		echo "Enter username:";

		$result = null;
		$isExisted = true;
		while($isExisted) {
			$handle = fopen ("php://stdin","r");
			$username = trim(fgets($handle));
			fclose($handle);
			if(!empty($username)) {
                $isUserExisted = $this->findUserByUsername($username);
                if((empty($isUserExisted) && $isNew) || (!empty($isUserExisted) && !$isNew)) {
                    $this->setUsername($username);
                    $isExisted = false;
                    $result = $username;
                } elseif($isNew) {
                    echo "User `$username` is existed.\n";
                    echo "Please choose another username: ";
                } else {
                    echo "User `$username` is not existed.\n";
                }

			} else {
				echo "Username cannot be empty.\n";
				echo "Please type username: ";
			}
		}

		return $result;
	}

    /**
     * @param string $message
     * @return string|null
     */
    protected function getPasswordFromInput(string $message = "Enter password:")
	{

		echo $message;

		$result = null;
		$isValid = false;
		while(!$isValid) {
			$handle = fopen ("php://stdin","r");
			$password = trim(fgets($handle));
			fclose($handle);
			if(!empty($password)) {
                try {
                    if($this->setNewPassword($password)) {
                        $result = $password;
                        $isValid = true;
                    }
                } catch (Exception $e) {
                    echo "Input password is invalid.\n";
                    echo "ERROR: " . $e->getMessage() . "\n";
                    echo "Please choose another password: ";
                }

			} else {
				echo "Password cannot be empty.\n";
				echo "Please type password: ";
			}
		}
		return $result;
	}

    /**
     * @param string $password
     * @return string
     */
    protected function encrypt(string $password)
	{
		return md5($password);
	}

    /**
     * @param string $password
     * @return bool
     */
    protected function verifyPassword(string $password)
	{
		return $password == $this->password;
	}

	protected function openStorage()
	{
		if(file_exists(self::STORAGE_FILE_NAME)) {
			$storage = fopen(self::STORAGE_FILE_NAME, 'a+') or exit("Unable to open file!");
		} else {
			$storage = fopen(self::STORAGE_FILE_NAME, 'w+') or exit("Can't create file!");
		}

		return $storage;
	}

    /**
     * @param string $username
     * @return null
     */
    protected function findUserByUsername(string $username)
	{
		$user = null;
		$storage = $this->openStorage();

		while (!feof($storage)) {
		    $line = fgets($storage);
		    $line = explode('-', $line);
		    if($username == $line[0]) {
		    	$user['username'] = trim($line[0]);
		    	$user['password'] = trim($line[1]);
		    	break;
		    }
		}

		return $user;
	}

    /**
     * @return bool
     */
    protected function createUser()
	{
		$result = false;
		$storage = $this->openStorage();

		$content = $this->username . '-' . $this->password . PHP_EOL;
	    if (fwrite($storage, $content) != FALSE) {
	        $result = true;
	    }
	    fclose($storage);

		return $result;
	}

}
