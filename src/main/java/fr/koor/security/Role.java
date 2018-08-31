package fr.koor.security;

import java.io.Serializable;

/**
 * This class represents the concept of role. A role is associated with a or more users
 * (eg the user John Doe who has an administrator role).
 * 
 * @author Infini Software - Dominique Liard
 * @since 0.3.6
 */
public interface Role extends Serializable {

	
	/**
	 * Returns the unique identifier for this role.
	 * 
	 * @return The unique identifier.
	 */
	public int getIdentifier();
	
	/**
	 * Returns the name of this role.
	 * 
	 * @return Role name.
	 * 
	 * @see fr.koor.security.Role#setRoleName
	 */
	public String getRoleName();
	
	/**
	 * Changes the name of this role.
	 * 
	 * @param newRoleName	The new name of the role.
	 *  
	 * @see fr.koor.security.Role#getRoleName
	 */
	public void setRoleName( String newRoleName );	

}
