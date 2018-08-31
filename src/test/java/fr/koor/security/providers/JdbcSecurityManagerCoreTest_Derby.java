package fr.koor.security.providers;

import org.junit.AfterClass;
import org.junit.Test;

import fr.koor.utility.DataSource;
import fr.koor.utility.FileSystem;


public class JdbcSecurityManagerCoreTest_Derby extends JdbcSecurityManagerCoreTest {

	private static final String DATABASE_LOCATION = "src/test/resources/security.db";
	
	public JdbcSecurityManagerCoreTest_Derby() {
		this.dataSource = new DataSource() {
			@Override public String getConnectionURL() { return "jdbc:derby:" + DATABASE_LOCATION + ";create=true"; }
			@Override public String getPassword() {	return ""; }
			@Override public String getLogin() { return ""; }
			@Override public String getDriverClassName() { return "org.apache.derby.jdbc.EmbeddedDriver"; }
		};
	}
	
	@AfterClass public static void removeDatabase() {
		try {
			FileSystem.delTree( DATABASE_LOCATION );
		} catch ( Exception exception ) {
			// NOTHING TO DO
		}
	}

	//--- Common tests ---
	
	@Test public void test_openSession() throws Exception { super.test_openSession(); }
	@Test public void test_UserMethods() throws Exception { super.test_UserMethods(); }
	@Test public void test_insertUser_alreadyRegistered() throws Exception { super.test_insertUser_alreadyRegistered(); }
	@Test public void test_updateUser() throws Exception { super.test_updateUser(); }

	@Test public void test_RoleMethods() throws Exception { super.test_RoleMethods(); }
	@Test public void test_UserRolesReferences() throws Exception { super.test_UserRolesReferences(); }
	
	@Test public void test_lastConnection() throws Exception { super.test_lastConnection(); }
	@Test public void test_sqlInjection() throws Exception { super.test_sqlInjection(); }
	
//	@Test
//	public void test_fisrtName_lastName_email() {
//		throw new RuntimeException();
//	}
	
	//--- Specific tests ---	
		
}
