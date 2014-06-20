<?php
include_once('pbkdf2.php');

// In case PHP < 5.3.0
if (!function_exists('quoted_printable_encode'))
{
	/**
	* Process a string to fit the requirements of RFC2045 section 6.7. Note that
	* this works, but replaces more characters than the minimum set. For readability
	* the spaces and CRLF pairs aren't encoded though.
	*/
	function quoted_printable_encode($string) {
		$string = str_replace(array('%20', '%0D%0A', '%'), array(' ', "\r\n", '='), rawurlencode($string));
		$string = preg_replace('/[^\r\n]{73}[^=\r\n]{2}/', "$0=\r\n", $string);

		return $string;
	}
}

class ulPassword
{
	public static function Generate($length = 9, $add_dashes = false, $available_sets = 'luds')
	{
		// Frankly, this is not really my own code, but I don't know anymore where I got it from.

    // Generates a strong password of N length containing at least one lower case letter,
		// one uppercase letter, one digit, and one special character. The remaining characters
		// in the password are chosen at random from those four sets.
		//
		// The available characters in each set are user friendly - there are no ambiguous
		// characters such as i, l, 1, o, 0, etc. This, coupled with the $add_dashes option,
		// makes it much easier for users to manually type or speak their passwords.
		//
		// Note: the $add_dashes option will increase the length of the password by
		// floor(sqrt(N)) characters.

		$sets = array();
		if(strpos($available_sets, 'l') !== false)
			$sets[] = 'abcdefghjkmnpqrstuvwxyz';
		if(strpos($available_sets, 'u') !== false)
			$sets[] = 'ABCDEFGHJKMNPQRSTUVWXYZ';
		if(strpos($available_sets, 'd') !== false)
			$sets[] = '23456789';
		if(strpos($available_sets, 's') !== false)
			$sets[] = '!@#$%&*?';

		$all = '';
		$password = '';
		foreach($sets as $set)
		{
			$password .= $set[array_rand(str_split($set))];
			$all .= $set;
		}

		$all = str_split($all);
		for($i = 0; $i < $length - count($sets); $i++)
			$password .= $all[array_rand($all)];

		$password = str_shuffle($password);

		if(!$add_dashes)
			return $password;

		$dash_len = floor(sqrt($length));
		$dash_str = '';
		while(strlen($password) > $dash_len)
		{
			$dash_str .= substr($password, 0, $dash_len) . '-';
			$password = substr($password, $dash_len);
		}
		$dash_str .= $password;
		return $dash_str;
	}

	// Returns the number of entropy bits in a password,
	// based on a pessimistic guess (assuming the attacker has
	// information on the used character classes and the number
	// of repeated characters). Based on a 94-letter printable alphabet.
	public static function GetEntropy($pwd)
	{
		// Get the number of unique characters
		$chars = str_split($pwd);
		$unique_chars = sizeof(array_unique($chars));

		// Get the size of the character pool
		$pool_size = 0;
		if (preg_match('/[a-z]/', $pwd))
			$pool_size += 26;
		if (preg_match('/[A-Z]/', $pwd))
			$pool_size += 26;
		if (preg_match('/[0-9]/', $pwd))
			$pool_size += 10;
		if (preg_match('/[^A-Za-z0-9]/', $pwd))
			$pool_size += 32;

		// Calculate entropy
		$pwd_length = $unique_chars;
		$bits_per_char = log($pool_size, 2);
		return floor($pwd_length*$bits_per_char);
	}

	// Returns a score 0-20 estimating the strength of a password.
	// Strengths above 10 are for the paranoid and a score of 10
	// should already be considered a good password in general, unless
	// there is some explicit need for stronger passwords.
	public static function GetStrength($pwd, $username=NULL)
	{
		// Check if it is any of the common passwords
		$pwdlist = UL_INC_DIR.'/data/pwdlist';
		if (fie_exists($pwdlist))
		{
			$lines = file($pwdlist, FILE_IGNORE_NEW_LINES);
			if (ulUtils::in_array($pwd, $lines))
				return 1;
		}

		// Add a score for every 9 bits of entropy
		$entropy = self::GetEntropy($pwd);
		$score = $entropy / 9;

		// Halve if username is in the string
		if (!empty($username))
		{
			if ($pwd == $username)
				return 1;
			if (stripos($pwd, $username) !== false)
				$score /= 2;
		}

		return floor($score);
	}

	private static function PreProcess($str)
	{
		// Workaround for CVE-2011-2483, corrected in PHP 5.3.7
		// This bug in crypt_blowfish reduces hash strength for some strings
		// that have 8bit chars in them. quoted_printable_encode only touches 8bit chars
		// and encodes them to 7bit chars.

		return quoted_printable_encode($str);
	}

	public static function IsValid($str)
	{
		if ($str=='')
			return true;

		$str = self::PreProcess($str);

		// Cap user input to maximum length
		if (strlen($str) > UL_MAX_PASSWORD_LENGTH)
			return false;

		return true;
	}

	private static function BCryptSalt()
	{
		$salt_prefix = sprintf('$2a$%02d$', UL_PWD_ROUNDS);

		// Returns a properly formatted blowfish salt ( 7 bytes prefix + 22 bytes blowfish salt)
		return $salt_prefix . self::GensaltBlowfish( ulUtils::RandomBytes(16) );
	}

    private static function GensaltBlowfish($input)
	{
		// See: http://stackoverflow.com/questions/4795385/how-do-you-use-bcrypt-for-hashing-passwords-in-php
		// Input string must be 16 bytes min. Anything after 16 is ignored.

		// The following is code from the PHP Password Hashing Framework
		// http://www.openwall.com/phpass/
		//
		// We care because the last character in our encoded string will
		// only represent 2 bits.  While two known implementations of
		// bcrypt will happily accept and correct a salt string which
		// has the 4 unused bits set to non-zero, we do not want to take
		// chances and we also do not want to waste an additional byte
		// of entropy.
		$itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

		$output = '';
		$i = 0;
		do {
			$c1 = ord($input[$i++]);
			$output .= $itoa64[$c1 >> 2];
			$c1 = ($c1 & 0x03) << 4;
			if ($i >= 16) {
				$output .= $itoa64[$c1];
				break;
			}

			$c2 = ord($input[$i++]);
			$c1 |= $c2 >> 4;
			$output .= $itoa64[$c1];
			$c1 = ($c2 & 0x0f) << 2;

			$c2 = ord($input[$i++]);
			$c1 |= $c2 >> 6;
			$output .= $itoa64[$c1];
			$output .= $itoa64[$c2 & 0x3f];
		} while (1);

		return $output;

	}

	public static function Hash($password, $salt = '')
	{
		if (ulUtils::BeginsWith($salt, '{SSHA}'))
		{
			$salt = substr($salt, 6);
			if ($salt == '') $salt = ulUtils::RandomBytes(24, true);
			return '{SSHA}' . base64_encode( pack( 'H*', sha1( $password.$salt ) ).$salt );
		}
		else if (ulUtils::BeginsWith($salt, '{SHA}'))
		{
			return '{SHA}' . base64_encode( pack( 'H*', sha1( $password ) ) );
		}
		else if (ulUtils::BeginsWith($salt, '{SMD5}'))
		{
			$salt = substr($salt, 6);
			if ($salt == '') $salt = ulUtils::RandomBytes(24, true);
			return '{SMD5}' . base64_encode( pack( 'H*', md5( $password.$salt ) ).$salt );
		}
		else if (ulUtils::BeginsWith($salt, '{MD5}'))
		{
			return '{MD5}' . base64_encode( pack( 'H*', md5( $password ) ) );
		}
		else if (ulUtils::BeginsWith($salt, '{CRYPT}'))
		{
			$salt = substr($salt, 7);
      if ($salt == '') $salt = self::BCryptSalt();

			// We must not preprocess here to stay compatible with other applications
			return '{CRYPT}'.crypt($password,  $salt);
		}
		else if (ulUtils::BeginsWith($salt, '{PBKDF2}'))
		{
      $hash_bytes = 96;
      $hash_algo = UL_HMAC_FUNC;
      $hash_rounds = pow(2,UL_PWD_ROUNDS);
			$salt = substr($salt, 8);
      if ($salt == '')
        $salt = ulUtils::RandomBytes(16, true);
      else
      {
        $parts = explode(':', $salt);
        $hash_algo = $parts[0];
        $hash_rounds = $parts[1];
        $salt = $parts[2];
      }

			// We must not preprocess here to stay compatible with other applications
      return '{PBKDF2}' . $hash_algo . ':' . $hash_rounds . ':' .  $salt . ':' . 
        base64_encode(pbkdf2(
            $hash_algo,
            $password,
            $salt,
            $hash_rounds,
            $hash_bytes,
            true
        ));
		}
		else
		{
      // For compatibility with older versions, an empty string is the same as '{BCRYPT}'
      if (ulUtils::BeginsWith($salt, '{BCRYPT}'))
        $salt = substr($salt, 8);
        
			if ($salt == '') $salt = self::BCryptSalt();
			return crypt(self::PreProcess($password),  $salt);
		}
	}

	private static function GetSaltFromHash($hash)
	{
		if (ulUtils::BeginsWith($hash, '{SSHA}'))
		{
			$hash = base64_decode(substr($hash, 6));
			return '{SSHA}'.substr($hash, 20);
		}
		else if (ulUtils::BeginsWith($hash, '{SHA}'))
		{
			return '{SHA}';
		}
		else if (ulUtils::BeginsWith($hash, '{SMD5}'))
		{
			$hash = base64_decode(substr($hash, 6));
			return '{SMD5}'.substr($hash, 16);
		}
		else if (ulUtils::BeginsWith($hash, '{MD5}'))
		{
			return '{MD5}';
		}
		else if (ulUtils::BeginsWith($hash, '{CRYPT}'))
		{
			$hash = substr($hash, 7);
			return '{CRYPT}'.substr($hash, 0, 29);
		}
		else if (ulUtils::BeginsWith($hash, '{PBKDF2}'))
		{
      $parts = explode(':', $hash);
      array_pop($parts);
      return implode(':', $parts);
		}
		else // Use our own choice, bcrypt
		{
			return substr($hash, 0, 29);
		}
	}

	public static function Verify($password, $stored_hash)
	{
		$salt = self::GetSaltFromHash($stored_hash);
		$calculated_hash = self::Hash($password, $salt);
		return ($calculated_hash == $stored_hash);
	}
}
?>