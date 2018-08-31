package fr.koor.security;

/**
 * This base class of exceptions is thrown when a user attempt a bad access into the secure system.
 * 
 * @see fr.koor.security.SecurityManagerException
 * 
 * @author Infini Software - Dominique Liard 
 * @since 0.3.6
 */
public class SecurityManagerException extends Exception {

    private static final long serialVersionUID = -7174841290024040340L;

	/**
     * Class constructor.
     * 
     * @param message The specific exception message to display.
     */
	public SecurityManagerException( String message ) {
		super( message );
	}

    /**
     * Class constructor.
     * 
     * @param message           The specific exception message to display.
     * @param innestException   The throwable that has thrown this exception.
     */
	public SecurityManagerException( String message, Throwable innestException ) {
		super( message, innestException );
	}
	
}
