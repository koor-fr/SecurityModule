package fr.koor.security.providers;

import org.junit.Test;

import fr.koor.utility.DataSource;

public class JdbcSecurityManagerCoreTest_MySql extends JdbcSecurityManagerCoreTest {

	public JdbcSecurityManagerCoreTest_MySql() {
		this.dataSource = new DataSource() {
			@Override public String getDriverClassName() { return "org.mariadb.jdbc.Driver"; }
			@Override public String getConnectionURL() { return "jdbc:mariadb://localhost/SecurityModule"; }
			@Override public String getLogin() { return "root"; }
			@Override public String getPassword() {	return ""; }
		};
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

	//--- Specific tests ---	
	
}
