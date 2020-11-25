package fr.koor.security.providers;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith( Suite.class )				
@Suite.SuiteClasses( {				
	JdbcSecurityManagerCoreTest.class,
	XmlSecurityManagerCoreTest.class,
	XmlSecurityManagerCoreTest2.class
} )		
public class JUnitTestSuite {				
}