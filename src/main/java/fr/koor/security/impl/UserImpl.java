package fr.koor.security.impl;

import java.beans.Transient;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import fr.koor.security.Role;
import fr.koor.security.SecurityManagerException;
import fr.koor.security.User;


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
public class UserImpl implements User {

	private static final long serialVersionUID = -1909817859035602141L;
	
	private transient fr.koor.security.SecurityManager securityManager;	
	private int 		identifier;
	private String 		login;
	private String 		password;
	private int 		connectionNumber;
	private Date 		lastConnection;
	private int 		consecutiveErrors;
	private boolean 	isDisabled;
	private Set<Role>  	roles = new HashSet<Role>();
	
	private String 		firstName = "";
	private String 		lastName = "";
	private String 		email = "";
	
	/**
	 * Default constructor.
	 */
	public UserImpl() { }
	
	/**
	 * You cannot directly create a User. The visibility of this constructor is restricted to the <code>fr.koor.security</code> package.
	 * Instead of, use an UserManager instance.
	 * 
	 * @param securityManager 	The security manager that produce this user.
	 * @param identifier		The unique identifier of this user.
	 * @param login				The login of this user.
	 * @param encryptedPassword	The password of this user. This password must be already encrypted. 
	 * 
	 * @throws SecurityManagerException Thrown when you forget to pass a valid SecurityManager
	 * 
	 * @see fr.koor.security.SecurityManager
	 */
	public UserImpl( fr.koor.security.SecurityManager securityManager, int identifier, String login, String encryptedPassword ) throws SecurityManagerException {
		if ( securityManager == null ) throw new NullPointerException();
		
		this.securityManager = securityManager;
		this.setIdentifier( identifier );
		this.setLogin( login );
		this.password = encryptedPassword;
		this.setConnectionNumber( 0 );
		this.setLastConnection( new Date() );
		this.setConsecutiveErrors( 0 );
		this.setDisabled( false );
	}
	
	
	/**
	 * Return the identifier of this user. Normaly, this identified is used as the primary key in the security storage
	 * engine (certainly a relational database). It must be unique within the database. Therefore, you cannot change the
	 * user identifier's.
	 *  
	 * @return The user identifier.
	 */
	public int getIdentifier() {
		return this.identifier;
	}
	

	/**
	 * Set the user identifier. Only the <code>fr.koor.security</code> package has visibility on this method.
	 * 
	 * @param identifier The new user identifier.
	 * 
	 * @see fr.koor.security.User #getIdentifier
	 * @see fr.koor.security.impl.UserImpl #getIdentifier
	 */
	public void setIdentifier( int identifier ) {
		this.identifier = identifier;
	}

	/**
	 * Returns the user login.
	 * @return The user login.
	 */
	public String getLogin() {
		return this.login;
	}

	/**
	 * Change the login for this user.
	 * @param newLogin		The new login to store in this user.
	 */
	private void setLogin( String newLogin ) {
		if ( newLogin == null ) throw new NullPointerException( "Login cannot be null" );
		this.login = newLogin;
	}

	/**
	 * Returns the user encoded password. This method is only accessible for <code>fr.koor.security</code> pacakge.
	 * @return The user encoded password.
	 */
	@Transient
	public String getPassword() {
		return this.password;
	}
	
	/**
	 * Check if the encrypted string (for the specified password) is the same that the encrypted password store in the used security system (certainly a relational
	 * database).
	 * 
	 * @param password	The clear password to compare
	 * @return	true if encrypted version of the password is the same that the user encrypted password. false otherwise. 
	 * 
	 * @throws SecurityManagerException Thrown if passwords cannot be compared.
	 * 
	 * @see fr.koor.security.impl.UserImpl#setPassword(String)
	 */
	@Override public boolean isSamePassword( String password ) throws SecurityManagerException {
		return this.securityManager.getUserManager().encryptPassword( password ).equals( this.password );
	}

	/**
	 * Set the new password for this user. Note that the password is stored in encrypted format.
	 * 
	 * @param newPassword	The new password for this user.
	 * 
	 * @throws SecurityManagerException Thrown if security system cannot change the password.
	 * 
	 * @see fr.koor.security.impl.UserImpl#isSamePassword(String)
	 */
	@Override public void setPassword( String newPassword ) throws SecurityManagerException  {
		this.password = this.securityManager.getUserManager().encryptPassword( newPassword );
	}

	/**
	 * Returns the connection number of this user. The connection number is increased as each connection time.
	 * 
	 * @return The actual connection number.
	 * 
	 * @see fr.koor.security.impl.UserImpl#setConnectionNumber( int )
	 * @see fr.koor.security.UserManager#checkCredentials(String, String)
	 */
	@Override public int getConnectionNumber() {
		return this.connectionNumber;
	}

	/**
	 * Set the connection number for this user. This method is reserved for the <code>fr.koor.security</code> package.
	 * 
	 * @param newConnectionNumber	The new connection number.
	 * 
	 * @see fr.koor.security.User#getConnectionNumber()
	 */
	public void setConnectionNumber( int newConnectionNumber ) {
		this.connectionNumber = newConnectionNumber;
	}

	/**
	 * Returns the date and the time of the last connection for this user.
	 * 
	 * @return The date of the last connection.
	 * 
	 * @see fr.koor.security.impl.UserImpl#setLastConnection( Date )
	 */
	@Override public Date getLastConnection() {
		return this.lastConnection;
	}

	/**
	 * Set the date and the time of the last connection for this user.
	 *  
	 * @param lastConnection	The new date and the time of the last connection.
	 * 
	 * @see fr.koor.security.User#getLastConnection()
	 */
	public void setLastConnection( Date lastConnection ) {
		this.lastConnection = lastConnection;
	}
	
	/**
	 * Returns if the user account is disabled.
	 * 
	 * @return true is the user account is disabled, false otherwise.
	 * 
	 * @see fr.koor.security.impl.UserImpl#setDisabled( boolean )
	 */
	@Override public boolean isDisabled() {
		return this.isDisabled;
	}
	
	/**
	 * Set the disabled state for this user.
	 *  
	 * @param isDisabled	The disabled state.
	 * 
	 * @see fr.koor.security.User#isDisabled()
	 */
	public void setDisabled( boolean isDisabled ) {
		this.isDisabled = isDisabled;
	}
	
	/**
	 * Returns the consecutive error number 
	 * @return The  consecutive error number.
	 * 
	 * @see fr.koor.security.impl.UserImpl#setConsecutiveErrors( int )
	 */
	public int getConsecutiveErrors() {
		return consecutiveErrors;
	}
	
	/**
	 * Set the  consecutive error number.
	 *  
	 * @param consecutiveErrors	The consecutive errors value.
	 * 
	 * @see fr.koor.security.User#getConsecutiveErrors()
	 */
	public void setConsecutiveErrors( int consecutiveErrors ) {
		this.consecutiveErrors = consecutiveErrors;
	}
	
	/**
	 * Checks is this user is associated to the specified role.
	 * @param role	The expected role.
	 * @return true is this user has the specified role, false otherwize.
	 */
	@Override public boolean isMemberOfRole( Role role ) {
		return this.roles.contains( role );
	}

	/**
	 * Returns a set of all roles associated to this user..
	 * @return The set of roles.
	 */
	@Override public Set<Role> getRoles() {
		return this.roles;
	}
	
	/**
	 * Adds another role to this user.
	 * @param role	The new role to affect for this user.
	 */
	@Override public void addRole( Role role ) {
		this.roles.add( role );
	}
	
	/**
	 * Removes a role to this user.
	 * @param role	The role to remove for this user.
	 */
	@Override public void removeRole( Role role ) {
		if ( this.roles.contains( role ) )
			this.roles.remove( role );
	}
	
	/**
	 * Returns the first name of this user.	
	 * @return The first name
	 */
	@Override public String getFirstName() {
		return firstName;
	}
	
	/**
	 * Changes the first name of this user.
	 * @param firstName The new first name.
	 */
	public void setFirstName( String firstName ) {
		this.firstName = firstName;
	}
	
	/**
	 * Returns the last name of this user.	
	 * @return The last name
	 */
	@Override public String getLastName() {
		return lastName;
	}
	
	/**
	 * Changes the last name of this user.
	 * @param lastName The new last name.
	 */
	public void setLastName( String lastName ) {
		this.lastName = lastName;
	}
	
	/**
	 * Returns the full name (first name and last name) of this user.
	 * @return The full name.
	 */
	public String getFullName() {
		return this.getFirstName() + " " + this.getLastName();
	}
	
	/**
	 * Returns the email of this user.
	 * @return The email.
	 */
	@Override public String getEmail() {
		return email;
	}
	
	/**
	 * Changes the email of this user.
	 * @param email The new email.
	 */
	public void setEmail( String email ) {
		this.email = email;
	}
	
	
	/**
	 * Compute the representation string associted to this instance.
	 * @return The instance representation string 
	 */
	@Override
	public String toString() {
		return "idUser = " + this.getIdentifier() + " ; Login = " + this.getLogin();
	}
}
