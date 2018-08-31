package fr.koor.security.providers;

import org.junit.Assert;
import org.junit.Test;

import fr.koor.security.Role;
import fr.koor.security.RoleManager;
import fr.koor.security.User;
import fr.koor.security.UserManager;
import fr.koor.security.providers.XmlSecurityManager;

public class XmlSecurityManagerCoreTest2 {

	private static final String FILENAME = "src/test/java/fr/koor/security/providers/XmlSecurityManagerCoreTest2.xml";	
	
	@Test
	public void setUp() throws Exception {
		try ( fr.koor.security.SecurityManager securityManager = new XmlSecurityManager( FILENAME ) ) {
			UserManager userManager = securityManager.getUserManager();
			RoleManager roleManager = securityManager.getRoleManager();
	
			Role adminRole = roleManager.selectRoleByName( "Admin" );
			Role projectManagerRole = roleManager.selectRoleByName( "ProjectManager" );
			
			User user = userManager.checkCredentials( "domi", "coach" );
			Role role = user.getRoles().iterator().next();
	
			Assert.assertEquals( "domi", user.getLogin() );
			Assert.assertEquals( 1, user.getRoles().size() );
			Assert.assertEquals( "ProjectManager", role.getRoleName() );
			Assert.assertEquals( false, user.isMemberOfRole( adminRole ) );
			Assert.assertEquals( true, user.isMemberOfRole( projectManagerRole ) );
		}
	}

}
