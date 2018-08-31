package fr.koor.security;

import java.util.List;

/**
 * This interface defines the methods used to manage User instances.
 * To can get a UserManager instance by asking it at your SecurityManager.
 * 
 * @see fr.koor.security.SecurityManager
 * @see fr.koor.security.providers.JdbcSecurityManager
 * @see fr.koor.security.User
 * 
 * @author Dominique Liard
 * @since 0.3.6
 */
public interface UserManager {

	/**
	 * Check if the pair login/password represents an autorized user for the considered
	 * application. If the identity is rejected, an exception will thrown. If the
	 * identity is accepted, the connection number of the considered user is increased.
	 * 
	 * @param userLogin     The login for the considered user.
	 * @param userPassword  The password for the considered user.
	 * @return              The considered user instance.
	 * 
	 * @throws AccountDisabledException  Thrown when the provided account informations there invalid.
	 * @throws BadCredentialsException   Thrown if the identity is rejected.
	 */
	//public AuthentifiedUser checkCredentials( String userLogin, String userPassword ) throws AccountDisabledException, BadCredentialsException;
	public User checkCredentials( String userLogin, String userPassword ) throws AccountDisabledException, BadCredentialsException;
	
	/**
	 * Retreive the user instance that have the desired identifier.
	 * 
	 * @param userId	The user identifier (the primary key into the security database).
	 * @return The selected user instance.

	 * @exception SecurityManagerException
	 *            Thrown if the searched user don't exists.
	 *            
	 * @see #checkCredentials(String, String)
	 * @see #getUserByLogin(String)
	 */
	public User getUserById( int userId ) throws SecurityManagerException;
		
	/**
	 * Retreive the user instance by its login.
	 * 
	 * @param login		The user login.
	 * @return The selected user instance.

	 * @exception SecurityManagerException
	 *            Thrown if the searched user don't exists.
	 *            
	 * @see #checkCredentials(String, String)
	 * @see #getUserById(int)
	 * @since 0.5
	 */
	public User getUserByLogin( String login ) throws SecurityManagerException;
		
	/**
	 * Retreive all user instances associated to the specified role.
	 * 
	 * @param role		The role that contains expected users.
	 * @return A list of users member of this role.

	 * @exception SecurityManagerException
	 *            Thrown when the search can't finish.
	 *            
	 * @see #checkCredentials(String, String)
	 * @see #getUserById(int)
	 * @see #getUserByLogin(String)
	 * @since 0.5
	 */
	public List<User> getUsersByRole( Role role ) throws SecurityManagerException;
	
	/**
	 * Insert a new user in the security system. The new used has the specified
	 * login and the specified password.
	 * 
	 * @param login         The login for the considered user.
	 * @param password      The password for the considered user. The specified password
	 *                      is automaticly encoded by this method.
	 * @return              The new user instance.
	 * 
	 * @exception SecurityManagerException
	 *            Thrown if the new user cannot be inserted in the security system. 
	 * @exception UserAlreadyRegisteredException
	 *            Thrown if the specified login is already registered in the security system.
	 */
	public User insertUser( String login, String password ) throws UserAlreadyRegisteredException, SecurityManagerException ;
	
	/**
	 * Update informations, in the security system, for the specified user.
	 * 
	 * @param user  The user instance to update.
	 * 
	 * @throws SecurityManagerException
	 *         Thrown if this manager cannot update the user informations.
	 */
	public void updateUser( User user ) throws SecurityManagerException ;
	
	/**
	 * Delete the specified user from the security system.
	 * 
	 * @param user    The user to delete.
	 * 
	 * @throws SecurityManagerException
	 *         Thrown if this manager cannot remove the user.
	 */
	public void deleteUser( User user ) throws SecurityManagerException ;
	
	/** 
	 * Defines the algorithm used for encode password. User password is stored in 
	 * encoded format.
	 * 
	 * @param clearPassword       A password (in clear).
	 * @return                    The encoded password.
	 * 
	 * @throws SecurityManagerException
	 *         Thrown if password encription failed.
	 */
	public String encryptPassword( String clearPassword ) throws SecurityManagerException;
	
}
