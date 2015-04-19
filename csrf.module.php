<?php 
class csrfModule{
	
public function get_csrf(){
		//generate aes based csrf token
		$ip=$_SERVER['REMOTE_ADDR'];
		$ua=sha1($_SERVER['HTTP_USER_AGENT']);
		$ts=time();
		$random_string=self::generate_random_string();
		return AESEncryptCtr($ip.'|'.$ua.'|'.$ts.'|'.$random_string,CSRF_AES_SITE_KEY,256);
}
	
public function verify_csrf($csrf){
	//verify aes based csrf token
	$ip=$_SERVER['REMOTE_ADDR'];
	$ua=sha1($_SERVER['HTTP_USER_AGENT']);
	$ts=time();
	$csrf_data=explode("|", AESDecryptCtr($csrf,CSRF_AES_SITE_KEY,256));
	//match ip - or not verified
	if(isset($csrf_data[0])){if ($csrf_data [0] != $ip){return false;}}else{return false;}
	//match sha1(user agent) - or not verified
	if(isset($csrf_data[1])){if ($csrf_data [1] != $ua){return false;}}else{return false;}
	
	//check if timestamp not passed 5min (18000 seconds)
	if(isset($csrf_data[2])){if ($csrf_data[2]+18000<$ts){
			return false; //time passed
		}}else{return false;}
	return true; //if passed all tests
}

public function generate_random_string(){
	//generate 40 chars random string using openssl_random_pseudo_bytes
	$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	$random = openssl_random_pseudo_bytes(40);
	$alphabet_length = strlen($alphabet);
	$password = '';
	for ($i = 0; $i < 40; ++$i) {
		$password .= $alphabet[ord($random[$i]) % $alphabet_length];
	}
	return $password;
}

}
?>
