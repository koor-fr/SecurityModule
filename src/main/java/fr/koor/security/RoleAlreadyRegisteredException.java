package fr.koor.security;

/**
 * This type of exceptions is thrown when a role is already registered into the security manager.
 * 
 * @see fr.koor.security.SecurityManagerException
 * 
 * @author Dominique Liard
 * @since 0.3.6
 */
public class RoleAlreadyRegisteredException extends SecurityManagerException {
	
	private static final long serialVersionUID = 7892564530043430372L;

	/**
	 * Class constructor.
	 * 
	 * @param message The specific exception message to display.
	 */
	public RoleAlreadyRegisteredException( String message ) {
		super( message );
	}

	/**
	 * Class constructor.
	 * 
	 * @param message			The specific exception message to display.
	 * @param innestException	The throwable that has thrown this exception.
	 */
	public RoleAlreadyRegisteredException( String message, Throwable innestException ) {
		super( message, innestException );
	}	

}
