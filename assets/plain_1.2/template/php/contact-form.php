<?php

/**
 * Contact form script
 *
 * @package		Plain HTML Template
 * @author		Michal Šimonfy
 */

/* load configuration */
require_once('config.php');

/* on contact form submit with basic spam protection */
if (isset($_POST['name']) && empty($_POST['bot'])) {
	
	$errors = array();

	$visitor_name    = strip_tags($_POST['name']);
	$visitor_email   = strip_tags($_POST['email']);
	$visitor_message = strip_tags($_POST['message']);

	// Basic validation

		// Name is too short or missing
		if (strlen($visitor_name) < 2) {
			$errors['name'] = 'Please enter your name.';
		}

		// Short or empty message
		if (strlen($visitor_message) < 7) {
			$errors['message'] = 'Please enter your message.';
		}

		// Invalid e-mail
		if( !filter_var($visitor_email, FILTER_VALIDATE_EMAIL) ) {
			$errors['email'] = 'Please enter a valid email address.';
		}

	// validation is ok, process to send an e-mail
	if (!$errors) {

		$subject = 'New message from '.$visitor_email;
		
		$headers   = array();
		$headers[] = "MIME-Version: 1.0";
		$headers[] = "Content-type: text/plain; charset=utf-8";
		$headers[] = "From: ". $visitor_email;
		$headers[] = "Reply-To: ". $visitor_email;
		$headers[] = "X-Mailer: PHP/".phpversion();

		if (@mail($your_email, $subject, $visitor_message, implode("\r\n", $headers))) {

			$output['status'] = 1;

		} else {

			$errors['system'] = 'There was a problem sending your email';
		}

	} 

	// There were some errors, show them to the visitor
	$output['errors'] = implode($errors,'<br />');

	// json print of output
	die(json_encode($output));

}

/* End of file contact-form.php */
/* Location: php/contact-form */