package fr.koor.security.impl;

import fr.koor.security.Role;

/**
 * This class represents the concept of role. A role is associated with a or more users
 * (eg the user John Doe who has an administrator role).
 * 
 * @author Dominique Liard
 * @since 0.3.6
 */
public class RoleImpl implements Role {

	private static final long serialVersionUID = -7766498032922073988L;

	private int identifier;
	private String roleName;
	
	/**
	 * Default constructor.
	 */
	public RoleImpl() { }
	
	/**
	 * You cannot directly create a Role. Instead of, use an RoleManager instance.
	 * 
	 * @param identifier	The role identifier.
	 * @param roleName		The name of the new role.
	 * 
	 * @see fr.koor.security.SecurityManager
	 */
	public RoleImpl( int identifier, String roleName ) {
		this.setIdentifier( identifier );
		this.setRoleName( roleName );
	}
	
	/**
	 * Returns the unique identifier for this role.
	 * 
	 * @return The unique identifier.
	 * 
	 * @see fr.koor.security.impl.RoleImpl#setIdentifier
	 */
	public int getIdentifier() {
		return this.identifier;
	}
	
	/**
	 * Changes the identifier for this user. Only classes of the <code>fr.koor.security</code> package can use this method.
	 * 
	 * @param newIdentifier		The new identifier for this role.
	 * 
	 * @see fr.koor.security.Role#getIdentifier
	 */
	void setIdentifier( int newIdentifier ) {
		this.identifier = newIdentifier;
	}
	
	/**
	 * Returns the name of this role.
	 * 
	 * @return Role name.
	 * 
	 * @see fr.koor.security.impl.RoleImpl#setRoleName
	 */
	public String getRoleName() {
		return this.roleName;
	}
	
	/**
	 * Changes the name of this role.
	 * 
	 * @param newRoleName	The new name of the role.
	 *  
	 * @see fr.koor.security.Role#getRoleName
	 */
	public void setRoleName( String newRoleName ) {
		this.roleName = newRoleName;
	}
	
	@Override
	public int hashCode() {
		return this.getIdentifier();
	}
	
	
	@Override
	public boolean equals( Object obj ) {
		return this.getIdentifier() == ( (RoleImpl) obj ).getIdentifier();
	}
}
