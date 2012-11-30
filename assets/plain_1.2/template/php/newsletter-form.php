<?php

/**
 * Newsletter script
 *
 * @package		Plain HTML Template
 * @author		Michal Šimonfy
 */

/* load configuration */
require_once('config.php');

/* on newsletter form submit with basic spam protection */
if (isset($_POST['subscribe']) && empty($_POST['bot'])) {
	
	$errors = array();

	$visitor_email   = strip_tags($_POST['subscribe']);

	// Basic validation - validate email
	if( !filter_var($visitor_email, FILTER_VALIDATE_EMAIL) ) {
		$errors['email'] = 'Please enter a valid email address.';
	}

	// validation is ok, process to send an e-mail
	if (!$errors) {

		$subject = 'New newsletter subscription from '.$visitor_email;
		$message = 'Congratulations, you have new subscriber "'.$visitor_email.'" at http://'.$_SERVER['HTTP_HOST'];
		
		$headers   = array();
		$headers[] = "MIME-Version: 1.0";
		$headers[] = "Content-type: text/plain; charset=utf-8";
		$headers[] = "From: ". $visitor_email;
		$headers[] = "Reply-To: ". $visitor_email;
		$headers[] = "X-Mailer: PHP/".phpversion();

		if (@mail($your_email, $subject, $message, implode("\r\n", $headers))) {

			$output['status'] = 1;

		} else {

			$errors['system'] = 'There was an error.';
		}

	} 

	// There were some errors, show them to the visitor
	$output['errors'] = implode($errors,'<br />');

	// json print of output
	die(json_encode($output));

}

/* End of file newsletter-form.php */
/* Location: php/newsletter-form */