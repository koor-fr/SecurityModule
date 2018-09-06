package fr.koor.security.providers;

import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.Date;

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
import fr.koor.utility.DataSource;

abstract public class JdbcSecurityManagerCoreTest {

	protected DataSource dataSource = null;
	protected JdbcSecurityManager securityManager = null;

	private String testedUserLogin = "toto's";
	private String testedUserPassword = "titi's";
	
	
	@Before public void setUp() {
		try {
			//Class.forName( this.dataSource.getDriverClassName() );
			this.securityManager = new JdbcSecurityManager( this.dataSource );
		} catch ( Exception exception ) {
			throw new RuntimeException( exception );
		}
	}

	@After public void tearDown() {
		try {
			try {
				Method getConnectionMethod = JdbcSecurityManager.class.getDeclaredMethod( "getConnection" );
				getConnectionMethod.setAccessible( true );
				Connection connection = (Connection) getConnectionMethod.invoke( this.securityManager );
				
				String strSql = "DELETE FROM T_USERS WHERE Login='" + testedUserLogin.replace( "'", "''" ) + "'";
				connection.createStatement().executeUpdate( strSql );

				strSql = "DELETE FROM T_ROLES";
				connection.createStatement().executeUpdate( strSql );

			} catch ( Exception exception ) {
				// User previously deleted. It's correct.
			}
			this.securityManager.close();				
		} catch ( Exception exception ) {
			throw new RuntimeException( exception );
		}
	}

	
	public void test_openSession() throws Exception {
		Method getConnectionMethod = JdbcSecurityManager.class.getDeclaredMethod( "getConnection" );
		getConnectionMethod.setAccessible( true );
		DatabaseMetaData metaData = ( (Connection) getConnectionMethod.invoke( this.securityManager ) ).getMetaData();
		String [] tableNames = { "T_USERS", "T_ROLES", "T_USER_ROLES" };
		ResultSet rsTables = metaData.getTables( null, null, null, new String[] { "TABLE" } );
		int count = 0;
		while ( rsTables.next() ) {
			String tableName = rsTables.getString( "TABLE_NAME" );
			for ( int i=0; i<tableNames.length; i++ ) {
				if ( tableName.equalsIgnoreCase( tableNames[i] ) ) count ++;
			}
		}
		if ( count < tableNames.length ) throw new RuntimeException( "Find only " + count + " tables" );
	}

	
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
				} catch ( AccountDisabledException e ) {
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
	
	public void test_updateUser() throws Exception {
		UserManager userManager = this.securityManager.getUserManager();
		User user = userManager.insertUser( this.testedUserLogin, this.testedUserPassword );

		// This first call updates the connection number and the last connection time
		user = userManager.checkCredentials( this.testedUserLogin, this.testedUserPassword );
		if ( user.getConnectionNumber() != 1 ) throw new Exception( "Bad connection number. Must be 1." );
		
		// This second call force SQL select statement execution and new update
		user = userManager.checkCredentials( this.testedUserLogin, this.testedUserPassword );
		if ( user.getConnectionNumber() != 2 ) throw new Exception( "Bad connection number. Must be 2." );
				
		userManager.deleteUser( user );		
	}
	
	@Test public void test_encryptPassword() throws Exception { 
		UserManager userManager = this.securityManager.getUserManager();
		if ( userManager.encryptPassword( "Ellipse" ).equals( "39s6tkG+ZRAb0hR0YNSohRDYR4w*" ) == false ) {
			throw new Exception( "Bad password encryption" );
		}
	}
	
	public void test_RoleMethods() throws Exception {
		String roleName = "Administrator";
		String newRoleName = "Admin2";
		
		RoleManager roleManager = this.securityManager.getRoleManager();
		Role role = null;
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
			roleManager.selectRoleByName( newRoleName );
			throw new Exception( "Role exists" );
		} catch ( SecurityManagerException exception ) {
			// Nothing to do
		}
	}
	
	public void test_UserRolesReferences() throws Exception {
		UserManager userManager = this.securityManager.getUserManager();
		RoleManager roleManager = this.securityManager.getRoleManager();

		User user = userManager.insertUser( this.testedUserLogin, this.testedUserPassword );
		Role role1 = roleManager.insertRole( "Administrator" );	
		Role role2 = roleManager.insertRole( "Client" );
		user.addRole( role1 );
		user.addRole( role1 ); // test voir s'il n'est pas ajouté deux fois
		user.addRole( role2 );
		
		userManager.updateUser( user );
		
		try {
			// Test
			User user2 = userManager.checkCredentials( this.testedUserLogin, this.testedUserPassword );
			if ( user2.getRoles().size() != 2 ) throw new Exception( "Bad role set size" );
			
			user2.removeRole( role2 );
			userManager.updateUser( user2 );
			
			Assert.assertEquals( false, user2.isMemberOfRole( role2 ) );
			
			User user3 = userManager.getUserById( user.getIdentifier() );
			
			Assert.assertEquals( true, user3.getLogin().equals( user.getLogin() ) );
			Assert.assertEquals( true, user3.getIdentifier() == user.getIdentifier() );
			
			userManager.deleteUser( user );	
			roleManager.deleteRole( role1 );
			roleManager.deleteRole( role2 );
		} finally {			
			boolean rolesAreDeleted = true;
			try { roleManager.selectRoleByName( "Administrator" );  rolesAreDeleted = false; } catch ( SecurityManagerException exception ) { }
			try { roleManager.selectRoleByName( "Client" );  rolesAreDeleted = false; } catch ( SecurityManagerException exception ) { }
			
			roleManager.deleteRole( role1 );
			roleManager.deleteRole( role2 );
			
			Assert.assertTrue( rolesAreDeleted );
		}
	}
	
	public void test_lastConnection() throws Exception {
		UserManager userManager = this.securityManager.getUserManager();
		userManager.insertUser( this.testedUserLogin, this.testedUserPassword );
		Date referenceDate = new Date();
		Thread.sleep( 10 );
		
		User user = userManager.checkCredentials( this.testedUserLogin, this.testedUserPassword );
		Assert.assertTrue( user.getLastConnection().after( referenceDate ) );
	}

	public void test_sqlInjection() throws Exception {
		UserManager userManager = this.securityManager.getUserManager();
		userManager.insertUser( this.testedUserLogin, this.testedUserPassword );

		try {
			userManager.checkCredentials( "toto' or 1=1 -- ", "toto' or 1=1 -- " );
			Assert.fail();
		} catch ( BadCredentialsException exception ) {
			// Ok
		}

		try {
			userManager.checkCredentials( "toto\\' or 1=1 -- ", "toto\\' or 1=1 -- " );
			Assert.fail();
		} catch ( BadCredentialsException exception ) {
			// Ok
		}

		try {
			userManager.checkCredentials( "toto\\'' or 1=1 -- ", "toto\\'' or 1=1 -- " );
			Assert.fail();
		} catch ( BadCredentialsException exception ) {
			// Ok
		}

		try {
			userManager.checkCredentials( "toto\\''' or 1=1 -- ", "toto\\''' or 1=1 -- " );
			Assert.fail();
		} catch ( BadCredentialsException exception ) {
			// Ok
		}
		
		userManager.checkCredentials( this.testedUserLogin, this.testedUserPassword );
	}

}
