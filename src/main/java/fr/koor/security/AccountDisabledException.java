package fr.koor.security;

/**
 * This exception type is thrown when the account is disabled.
 * 
 * @author Infini Software - Dominique Liard
 * @since 0.4.0
 */
public class AccountDisabledException extends SecurityManagerException {
	
	private static final long serialVersionUID = 5850951634979180174L;

	/**
	 * Class constructor
	 * @param message	The exception message
	 */
	public AccountDisabledException( String message ) {
		super( message );
	}

	/**
	 * Class constructor
	 * @param message			The exception message.
	 * @param innestException	The innest exception.
	 */
	public AccountDisabledException( String message, Throwable innestException ) {
		super( message, innestException );
	}	

}
