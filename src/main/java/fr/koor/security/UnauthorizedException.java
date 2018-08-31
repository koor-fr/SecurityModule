package fr.koor.security;

/**
 * This type of exceptions is thrown when a unauthorized user attempt to login into the secure system.
 * 
 * @see fr.koor.security.SecurityManagerException
 * 
 * @author Infini Software - Dominique Liard 
 * @since 0.3.6
 */
public class UnauthorizedException extends SecurityManagerException {

	private static final long serialVersionUID = -2165995801882052449L;

	/**
     * Class constructor.
	 */
	public UnauthorizedException() {
		super( "Unauthorized Exception" );
	}
	
    /**
     * Class constructor.
     * 
     * @param message The specific exception message to display.
     */
	public UnauthorizedException( String message ) {
		super( message );
	}

    /**
     * Class constructor.
     * 
     * @param message           The specific exception message to display.
     * @param innestException   The throwable that has thrown this exception.
     */
	public UnauthorizedException( String message, Throwable innestException ) {
		super( message, innestException );
	}	

}
