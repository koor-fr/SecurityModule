package fr.koor.security;

import java.io.Serializable;
import java.util.Date;
import java.util.Set;


/**
 * This class represents the concept of user for a considered computer system.
 * A user has a number of attributes and a set of roles assigned to it.
 * <br><br>
 * Note: you cannot directly create a User. Instead of, use an UserManager instance.
 * 
 * @see fr.koor.security.Role
 * @see fr.koor.security.RoleManager
 * @see fr.koor.security.SecurityManager
 * @see fr.koor.security.UserManager
 * 
 * @author Dominique Liard
 * @since 0.3.6
 */
public interface User extends Serializable {
	
	
	/**
	 * Return the identifier of this user. Normaly, this identified is used as the primary key in the security storage
	 * engine (certainly a relational database). It must be unique within the database. Therefore, you cannot change the
	 * user identifier's.
	 *  
	 * @return The user identifier.
	 */
	public int getIdentifier();
	


	/**
	 * Returns the user login.
	 * @return The user login.
	 */
	public String getLogin();

	
	/**
	 * Check if the encrypted string (for the specified password) is the same that the encrypted password store in the used security system (certainly a relational
	 * database).
	 * 
	 * @param password	The clear password to compare
	 * @return	true if encrypted version of the password is the same that the user encrypted password. false otherwise. 
	 * 
	 * @throws SecurityManagerException Thrown if passwords cannot be compared.
	 * 
	 * @see fr.koor.security.User#setPassword(String)
	 */
	public boolean isSamePassword( String password ) throws SecurityManagerException;

	/**
	 * Set the new password for this user. Note that the password is stored in encrypted format.
	 * 
	 * @param newPassword	The new password for this user.
	 * 
	 * @throws SecurityManagerException Thrown if security system cannot change the password.
	 * 
	 * @see fr.koor.security.User#isSamePassword(String)
	 */
	public void setPassword( String newPassword ) throws SecurityManagerException;

	/**
	 * Returns the connection number of this user. The connection number is increased as each connection time.
	 * 
	 * @return The actual connection number.
	 */
	public int getConnectionNumber();

	/**
	 * Returns the date and the time of the last connection for this user.
	 * 
	 * @return The date of the last connection.
	 */
	public Date getLastConnection();

	
	/**
	 * Returns if the user account is disabled.
	 * 
	 * @return true is the user account is disabled, false otherwise.
	 */
	public boolean isDisabled();
	
	
	/**
	 * Returns the consecutive errors number 
	 * @return The  consecutive errors number.
	 */
	public int getConsecutiveErrors();
	
	/**
	 * Returns the first name of this user.	
	 * @return The first name.
	 */
	public String getFirstName();
	
	/**
	 * Returns the last name of this user.	
	 * @return The last name.
	 */
	public String getLastName();
	
	/**
	 * Returns the full name (first name and last name) of this user.
	 * @return The full name.
	 */
	public String getFullName();
	
	/**
	 * Returns the email of this user.
	 * @return The email.
	 */
	public String getEmail();
	
	/**
	 * Checks is this user is associated to the specified role.
	 * @param role	The expected role.
	 * @return true is this user has the specified role, false otherwize.
	 */
	public boolean isMemberOfRole( Role role );

	/**
	 * Returns a set of all roles associated to this user..
	 * @return The set of roles.
	 */
	public Set<Role> getRoles();
	
	/**
	 * Adds another role to this user.
	 * @param role	The new role to affect for this user.
	 */
	public void addRole( Role role );
	
	/**
	 * Removes a role to this user.
	 * @param role	The role to remove for this user.
	 */
	public void removeRole( Role role );
	
}
