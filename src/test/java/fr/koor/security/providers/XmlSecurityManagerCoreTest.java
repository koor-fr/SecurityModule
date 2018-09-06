package fr.koor.security.providers;

import java.util.Date;
import java.util.Set;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import fr.koor.security.AccountDisabledException;
import fr.koor.security.BadCredentialsException;
import fr.koor.security.Role;
import fr.koor.security.RoleManager;
import fr.koor.security.SecurityManagerException;
import fr.koor.security.User;
import fr.koor.security.UserManager;
import fr.koor.security.impl.UserImpl;
import fr.koor.utility.FileSystem;

public class XmlSecurityManagerCoreTest {

	private static final String FILENAME = "src/test/java/fr/koor/security/providers/SecurityDB.xml";
	
	private String testedUserLogin = "toto's";
	private String testedUserPassword = "titi's";

	protected fr.koor.security.SecurityManager securityManager = null;
	
	@Before public void setUp() {
		try {
			this.securityManager = new XmlSecurityManager( FILENAME );
		} catch ( Exception exception ) {
			throw new RuntimeException( exception );
		}
	}

	@After public void tearDown() {
		try {
			this.securityManager.close();				
		} catch ( Exception exception ) {
			throw new RuntimeException( exception );
		}
		try {
			FileSystem.delete( FILENAME );
		} catch ( Exception exception ) {
			throw new RuntimeException( exception );
		}
		Assert.assertFalse( FileSystem.isExisting( FILENAME ) );
		
	}

	@Test
	public void test_openSession() throws Exception {
		Assert.assertTrue( FileSystem.isExisting( FILENAME ) );
		Assert.assertEquals( "admin", this.securityManager.getRoleManager().selectRoleById( 1 ).getRoleName() );
		Assert.assertEquals( "admin", this.securityManager.getRoleManager().selectRoleByName( "admin" ).getRoleName() );
	}
	
	
	@Test
	public void test_getUserById() throws Exception {
		UserManager userManager = this.securityManager.getUserManager();
		User user = userManager.getUserById( 1 );
		
		Assert.assertEquals( "root", user.getLogin() );
		Set<Role> roles = user.getRoles();
		Assert.assertEquals( 2, roles.size() );
		Assert.assertEquals( "admin", roles.iterator().next().getRoleName() );
	}

	
	@Test
	public void test_UserMethods() throws Exception {
		UserManager userManager = this.securityManager.getUserManager();
		User user = userManager.insertUser( this.testedUserLogin, this.testedUserPassword );
		
		Assert.assertEquals( 0 , user.getConsecutiveErrors() );
		Assert.assertEquals( false , user.isDisabled() );
		
		// Check a bad identity
		try {
			user = userManager.checkCredentials( "James", "Bond" );
			throw new Exception( "It's not possible" );
		} catch ( BadCredentialsException exception ) {
			// Ok : nothing to do
		}

		// Check a two consecutive errors (but good login)
		try {
			user = userManager.checkCredentials( this.testedUserLogin , "Bond" );
			throw new Exception( "It's not possible" );
		} catch ( BadCredentialsException exception ) {
			try {
				user = userManager.checkCredentials( this.testedUserLogin , "Bond" );
				throw new Exception( "It's not possible" );
			} catch ( BadCredentialsException exception1 ) {
				// Nothing to do
			}
		}
		
		
		// Check a good identity
		user = userManager.checkCredentials( this.testedUserLogin, this.testedUserPassword );
		Assert.assertEquals( 0 , user.getConsecutiveErrors() );
		Assert.assertEquals( false , user.isDisabled() );
		
		
		// Check a three consecutive errors
		try {
			user = userManager.checkCredentials( this.testedUserLogin , "Bond" );
			throw new Exception( "It's not possible" );
		} catch ( BadCredentialsException exception ) {
			try {
				user = userManager.checkCredentials( this.testedUserLogin , "Bond" );
				throw new Exception( "It's not possible" );
			} catch ( BadCredentialsException exception1 ) {
				try {
					user = userManager.checkCredentials( this.testedUserLogin , "Bond" );
					throw new Exception( "It's not possible" );
				} catch ( AccountDisabledException exception2 ) {
					// Ok : nothing to do
				}
			}
		}
		
		userManager.deleteUser( user );

		// L'utilisateur ne doit plus exister
		try {
			user = userManager.checkCredentials( this.testedUserLogin, this.testedUserPassword );
			throw new Exception( "It's not possible, user is normally removed" );
		} catch ( BadCredentialsException exception ) {
			// Ok : nothing to do
		}
	}

	@Test
	public void test_insertUser_alreadyRegistered() throws Exception {
		UserManager userManager = this.securityManager.getUserManager();
		User user = null;
		try {
			user = userManager.insertUser( this.testedUserLogin, this.testedUserPassword );
			try {
				userManager.insertUser( this.testedUserLogin, this.testedUserPassword );
				throw new RuntimeException( this.testedUserLogin + " login is registered two times" );
			} catch ( SecurityManagerException exception ) {
				// Test is ok
			}
		} finally {
			userManager.deleteUser( user );		
		}
	}
	
	@Test
	public void test_updateUser() throws Exception {
		UserManager userManager = this.securityManager.getUserManager();
		User user = userManager.insertUser( this.testedUserLogin, this.testedUserPassword );

		// This first call updates the connection number and the last connection time
		user = userManager.checkCredentials( this.testedUserLogin, this.testedUserPassword );
		if ( user.getConnectionNumber() != 1 ) throw new Exception( "Bad connection number. Must be 1." );
		
		// This second call force SQL select statement execution and new update
		user = userManager.checkCredentials( this.testedUserLogin, this.testedUserPassword );
		if ( user.getConnectionNumber() != 2 ) throw new Exception( "Bad connection number. Must be 2." );

		user.setPassword( "NewPassword" );
		user.addRole( this.securityManager.getRoleManager().selectRoleById( 1 ) );
		userManager.updateUser( user );
		
		user = userManager.getUserById( user.getIdentifier() );
		if ( user.getConnectionNumber() != 2 ) throw new Exception( "Bad connection number. Must be 2." );
		Assert.assertEquals( userManager.encryptPassword( "NewPassword" ), ( (UserImpl) user ).getPassword() );
		Assert.assertEquals( 1, user.getRoles().size() );
		Assert.assertEquals( "admin", user.getRoles().iterator().next().getRoleName() );
		
		userManager.deleteUser( user );		
	}
	
	@Test public void test_encryptPassword() throws Exception { 
		UserManager userManager = this.securityManager.getUserManager();
		if ( userManager.encryptPassword( "Ellipse" ).equals( "39s6tkG+ZRAb0hR0YNSohRDYR4w*" ) == false ) {
			throw new Exception( "Bad password encryption" );
		}
		//System.out.println( userManager.encryptPassword( "domi" ) );
	}
	
	@Test
	public void test_RoleMethods() throws Exception {
		String roleName = "Administrator";
		String newRoleName = "Admin2";
		
		RoleManager roleManager = this.securityManager.getRoleManager();
		Role role = null;
		
		// Vérification que le role n'existe pas
		try {
			roleManager.selectRoleByName( roleName );
			throw new Exception( "Role exists" );
		} catch ( SecurityManagerException exception ) {
			// Nothing to do
		}
		
		// Création et manipulation du role
		try {
			role = roleManager.insertRole( roleName );
		
			Role role2 = roleManager.selectRoleByName( roleName );
			if ( role.getIdentifier() !=  role2.getIdentifier() ) throw new Exception( "Not equals 1" );
			
			Role role3 = roleManager.selectRoleById( role.getIdentifier() );
			if ( role.getIdentifier() !=  role3.getIdentifier() ) throw new Exception( "Not equals 2" );

			role.setRoleName( newRoleName );
			roleManager.updateRole( role );
			
			Role role4 = roleManager.selectRoleById( role.getIdentifier() );
			if ( role4.getRoleName().equals( newRoleName ) == false ) throw new Exception( "Cannot retreive role" );
			
		} finally {
			roleManager.deleteRole( role );
		}
		
		// Vérification que le role n'existe plus
		try {
			Role badRole = roleManager.selectRoleByName( newRoleName );
			System.out.println( badRole );
			throw new Exception( "Role exists" );
		} catch ( SecurityManagerException exception ) {
			// Nothing to do
		}
	}
	
	@Test
	public void test_UserRolesReferences() throws Exception {
		UserManager userManager = this.securityManager.getUserManager();
		RoleManager roleManager = this.securityManager.getRoleManager();

		User user = userManager.insertUser( this.testedUserLogin, this.testedUserPassword );
		Role role1 = roleManager.insertRole( "Admin" );
		Assert.assertEquals( 2, role1.getIdentifier() );
		Role role2 = roleManager.insertRole( "Client" );
		Assert.assertEquals( 3, role2.getIdentifier() );
		user.addRole( role1 );
		user.addRole( role1 ); // test voir s'il n'est pas ajouté deux fois
		user.addRole( role2 );
		
		userManager.updateUser( user );
		
		// Test
		User user2 = userManager.checkCredentials( this.testedUserLogin, this.testedUserPassword );
		int roleSize = user2.getRoles().size();
		if ( roleSize != 2 ) throw new Exception( "Bad role set size (expected 2): " + roleSize );
		
		user2.removeRole( role2 );
		userManager.updateUser( user2 );
		
		Assert.assertEquals( false, user2.isMemberOfRole( role2 ) );
		
		User user3 = userManager.getUserById( user.getIdentifier() );
		
		Assert.assertEquals( true, user3.getLogin().equals( user.getLogin() ) );
		Assert.assertEquals( true, user3.getIdentifier() == user.getIdentifier() );
		
		userManager.deleteUser( user );	
		roleManager.deleteRole( role1 );
		roleManager.deleteRole( role2 );
	}
	
	@Test
	public void test_lastConnection() throws Exception {
		UserManager userManager = this.securityManager.getUserManager();
		userManager.insertUser( this.testedUserLogin, this.testedUserPassword );
		Date referenceDate = new Date();
		Thread.sleep( 10 );
		
		User user = userManager.checkCredentials( this.testedUserLogin, this.testedUserPassword );
		Assert.assertTrue( user.getLastConnection().after( referenceDate ) );
	}

	@Test
	public void test_xmlInjection() throws Exception {
		UserManager userManager = this.securityManager.getUserManager();

		try {
			userManager.checkCredentials( "toto'tata", "toto'tata" );
			Assert.fail();
		} catch ( BadCredentialsException exception ) {
			// Ok
		}

		try {
			userManager.checkCredentials( "toto\"tata", "toto\"tata" );
			Assert.fail();
		} catch ( BadCredentialsException exception ) {
			// Ok
		}

		try {
			userManager.checkCredentials( "toto&tata", "toto&tata" );
			Assert.fail();
		} catch ( BadCredentialsException exception ) {
			// Ok
		}

		try {
			userManager.checkCredentials( "toto<tata", "toto<tata" );
			Assert.fail();
		} catch ( BadCredentialsException exception ) {
			// Ok
		}

		try {
			userManager.checkCredentials( "toto>tata", "toto>tata" );
			Assert.fail();
		} catch ( BadCredentialsException exception ) {
			// Ok
		}

		User user = userManager.insertUser( "a'\"&<>", "a'\"&<>" );
//		TODO : finish this test ( &quot; is not correctly tested by checkCredentials ).
//		User user2 = userManager.checkCredentials( "a'\"&<>", "a'\"&<>" );
//		Assert.assertEquals( user.getLogin(), "a'\"&<>" );
//		Assert.assertEquals( user.getLogin(), user2.getLogin() );
//		Assert.assertEquals( ( (UserImpl) user ).getPassword(), ( (UserImpl) user2 ).getPassword() );
		userManager.deleteUser( user );
		
		userManager.insertUser( this.testedUserLogin, this.testedUserPassword );
		user = userManager.checkCredentials( this.testedUserLogin, this.testedUserPassword );
		userManager.deleteUser( user );
	}
	
	@Test
	public void test_fisrtName_lastName_email() throws Exception {
//		UserManager userManager = this.securityManager.getUserManager();
//		User user = userManager.checkCredentials( "root", "admin" );
//		Assert.assertEquals( "root", user.getFirstName() );
//		Assert.assertEquals( "administrator", user.getLastName() );
//		Assert.assertEquals( "", user.getEmail() );
	}

}
