package fr.koor.security;

/**
 * <p>
 *     This interface defines methods for access to a security service. A security
 *     service must provide two mechanisms: authentication and permissions management.
 *     Authentication consist to identify a user and enable him (or not) connecting
 *     to the considered system. The management of permissions allows, once the user
 *     authenticated, him to have an access (or not) to resources.
 * </p>
 * 
 * <p>
 *     In the current version of the Ellipse framework, only authentication is supported.
 *     But a future version of the framework will add the concepts of permissions. The
 *     Ellipse framework provides the JdbcSecurityManager class : this is, of course,
 *     an implementation of this interface that use a relational database to store
 *     the security informations.
 * </p>
 * 
 * @see fr.koor.security.providers.JdbcSecurityManager
 * @see fr.koor.security.RoleManager
 * @see fr.koor.security.UserManager
 * 
 * @author Dominique Liard
 * @since 0.3.6
 */
public interface SecurityManager extends AutoCloseable {

	/**
	 * Open a session to the considered security service.
	 * 
	 * @throws SecurityManagerException	Thrown when connection to the security
	 * 	       service cannot be established.
	 */
	public void openSession() throws SecurityManagerException;
	
	/**
	 * Close the session with the considered security service.
	 * 
	 * @throws SecurityManagerException	Thrown when connection to the security
	 *         service cannot be closed.
	 */
	public void close() throws SecurityManagerException;
	
	/**
	 * Returns the role manager associated to this security manager. 
	 * A role manager provided methods to manage roles.
	 * 
	 * @return The role manager associated to this security manager. 
	 */
	public RoleManager getRoleManager();
	
	/**
	 * Returns the user manager associated to this security manager.
	 * A user manager provided methods to manage users.
	 * 
	 * @return The user manager associated to this security manager. 
	 */
	public UserManager getUserManager();	
	
}
