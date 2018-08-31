package fr.koor.security.providers;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.security.MessageDigest;
import java.util.Date;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathException;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;

import fr.koor.security.AccountDisabledException;
import fr.koor.security.BadCredentialsException;
import fr.koor.security.Role;
import fr.koor.security.RoleAlreadyRegisteredException;
import fr.koor.security.RoleManager;
import fr.koor.security.SecurityManagerException;
import fr.koor.security.User;
import fr.koor.security.UserAlreadyRegisteredException;
import fr.koor.security.UserManager;
import fr.koor.security.impl.RoleImpl;
import fr.koor.security.impl.UserImpl;

/** 
 * <p>
 *     This security manager (see interface fr.koor.security.SercurityManager)  use a XML file to store the security informations.
 * </p>
 * 
 * @see fr.koor.security.SecurityManager
 * 
 * @author Infini Software : Dominique Liard
 * @since 0.5.0
 */
public class XmlSecurityManager implements fr.koor.security.SecurityManager {

	private String xmlFilename;
	private Document xmlDocument;
	private XPath xpath	= XPathFactory.newInstance().newXPath();
	
	private UserManager userManager = new XmlUserManager();
	private RoleManager roleManager = new XmlRoleManager();
	
	
	/**
	 * This constructor produces an instance of security manager that has based on a XML file.
	 * 
	 * @param filename					The name of the XML file.
	 * 
	 * @exception SecurityManagerException Thrown if the XML file cannot be opened.
	 */
	public XmlSecurityManager( String filename ) throws SecurityManagerException {
		if ( filename == null ) throw new NullPointerException();
		this.xmlFilename = filename;
		this.openSession();
	}
	
	private void constructDatabase() throws Exception {
		FileOutputStream fos = new FileOutputStream( this.xmlFilename );
		PrintStream stream = new PrintStream( fos );
		
		stream.println( "<?xml version='1.0' encoding='UTF-8' ?>" );
		stream.println( "<SecurityDatabase>" );
		stream.println( "    <Users>" );
		stream.println( "        <User id='1' login='root' password='" + userManager.encryptPassword( "admin" ) + "' connectionNumber='0' lastConnection='0' consecutiveErrors='0' isDisabled='false' firstName='root' lastName='administrator' email=''>" );
		stream.println( "            <RoleRef id='1' />" );
		stream.println( "        </User>" );
		stream.println( "    </Users>" );
		stream.println( "    <Roles>" );
		stream.println( "        <Role id='1' roleName='admin' />" );
		stream.println( "    </Roles>" );
		stream.println( "</SecurityDatabase>" );
		
		stream.close();
	}

	@Override public void openSession() throws SecurityManagerException {
		try {
			if ( ! new File( this.xmlFilename ).exists() ) {
				this.constructDatabase();
			}

			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();
			this.xmlDocument = builder.parse( this.xmlFilename );
			
		} catch ( Exception exception ) {
			throw new SecurityManagerException( "Cannot open XML security database", exception );
		}
	}

	@Override public void close() throws SecurityManagerException {
		this.xmlDocument = null;
	}

	@Override public RoleManager getRoleManager() {
		return this.roleManager;
	}

	@Override public UserManager getUserManager() {
		return this.userManager;
	}
	
	
	private class XmlUserManager implements UserManager {

		@Override public User checkCredentials( String userLogin, String userPassword ) throws AccountDisabledException, BadCredentialsException {
			if ( userLogin == null ) throw new NullPointerException();
			if ( userPassword == null ) throw new NullPointerException();

			String rawLogin = userLogin;
			userLogin = userLogin.replace( "\"", "&quot;" );
			
			try {
				userPassword = this.encryptPassword( userPassword );
				
				Element element = (Element) xpath.evaluate( "//User[@login=\"" + userLogin + "\" and @password='" + userPassword + "']" , xmlDocument, XPathConstants.NODE );				
				if ( element != null ) {
					// User informations update
					
					int identifier = Integer.parseInt( element.getAttribute( "id" ) );
					int connectionNumber =  Integer.parseInt( element.getAttribute( "connectionNumber" ) ) + 1;
					Date lastConnection = new Date();
					//int consecutiveError = Integer.parseInt( element.getAttribute( "consecutiveErrors" ) );
					boolean isDisabled = Boolean.parseBoolean( element.getAttribute( "isDisabled" ) );
					
					element.setAttribute( "connectionNumber", "" + connectionNumber );
					element.setAttribute( "lastConnection", "" + lastConnection.getTime() );
					saveXmlDocument();
					
					if ( isDisabled ) {
						throw new AccountDisabledException( "Account is disabled" );
					} else {
						element.setAttribute( "consecutiveErrors", "0" );
					}
				
					UserImpl user = new UserImpl( XmlSecurityManager.this, identifier, rawLogin, userPassword );
					user.setConnectionNumber( connectionNumber );
					user.setLastConnection( lastConnection );
					user.setConsecutiveErrors( 0 );
					user.setDisabled( isDisabled );
					// TODO user.setFirstName( firstName );
					
					// Associated roles loading
					NodeList roleReferences = (NodeList) xpath.evaluate( "RoleRef", element, XPathConstants.NODESET );
					RoleManager roleManager = XmlSecurityManager.this.getRoleManager();
					for ( int i=0; i<roleReferences.getLength(); i++ ) {
						Element node = (Element) roleReferences.item( i );
						user.addRole( roleManager.selectRoleById( Integer.parseInt( node.getAttribute( "id" ) ) ) );
					}
					return user;
				}
			} catch ( AccountDisabledException exception ) {
				throw exception;
			} catch ( Exception exception ) {
				throw new BadCredentialsException( "Can't check credentials", exception );
			}

			try {
				Element element = (Element) xpath.evaluate( "//User[@login=\"" + userLogin + "\"]" , xmlDocument, XPathConstants.NODE );
				if ( element != null ) {
					int consecutiveErrors = Integer.parseInt( element.getAttribute( "consecutiveErrors" ) ) + 1;
					boolean forceDisabling = ( consecutiveErrors == 3 ); 

					element.setAttribute( "consecutiveErrors", "" + consecutiveErrors );
					element.setAttribute( "isDisabled", "" + forceDisabling );
					saveXmlDocument();

					if ( forceDisabling ) {
						throw new AccountDisabledException( "Account is disabled" );
					}
				}
			} catch ( AccountDisabledException exception ) {
				throw exception;
			} catch ( Exception exception ) {
				exception.printStackTrace();
				throw new BadCredentialsException( "Your identity is rejected", exception );
			}
			
			throw new BadCredentialsException( "Your identity is rejected" );
		}

		@Override public User getUserById( int userId ) throws SecurityManagerException {
			try {
				Element element = (Element) xpath.evaluate( "//User[@id=" + userId + "]" , xmlDocument, XPathConstants.NODE );
				if ( element == null ) {
					throw new SecurityManagerException( "User identifier " + userId + " not found" );
				}
				String userLogin = element.getAttribute( "login" ).replace( "&apos;", "'" );
				UserImpl user = new UserImpl( XmlSecurityManager.this, userId, userLogin, element.getAttribute( "password" ) );
				user.setConnectionNumber( Integer.parseInt( element.getAttribute( "connectionNumber" ) ) );
				user.setLastConnection( new Date( Long.parseLong( element.getAttribute( "lastConnection" ) ) ) );
				user.setConsecutiveErrors( Integer.parseInt( element.getAttribute( "consecutiveErrors" ) ) );
				user.setDisabled( Boolean.parseBoolean( element.getAttribute( "isDisabled" ) ) );
				
				NodeList roleReferences = (NodeList) xpath.evaluate( "RoleRef", element, XPathConstants.NODESET );
				RoleManager roleManager = XmlSecurityManager.this.getRoleManager();
				for ( int i=0; i<roleReferences.getLength(); i++ ) {
					Element node = (Element) roleReferences.item( i );
					user.addRole( roleManager.selectRoleById( Integer.parseInt( node.getAttribute( "id" ) ) ) );
				}
				
				return user;
			} catch ( XPathExpressionException exception ) {
				throw new SecurityManagerException( "Cannot select user for identifier " + userId, exception );
			}
		}

		@Override public User getUserByLogin( String login ) throws SecurityManagerException {
			try {
				Element element = (Element) xpath.evaluate( "//User[@login=" + login + "]" , xmlDocument, XPathConstants.NODE );
				if ( element == null ) {
					throw new SecurityManagerException( "User login " + login + " not found" );
				}
				int identifier = Integer.parseInt( element.getAttribute( "identifier" ) );
				UserImpl user = new UserImpl( XmlSecurityManager.this, identifier, login, element.getAttribute( "password" ) );
				user.setConnectionNumber( Integer.parseInt( element.getAttribute( "connectionNumber" ) ) );
				user.setLastConnection( new Date( Long.parseLong( element.getAttribute( "lastConnection" ) ) ) );
				user.setConsecutiveErrors( Integer.parseInt( element.getAttribute( "consecutiveErrors" ) ) );
				user.setDisabled( Boolean.parseBoolean( element.getAttribute( "isDisabled" ) ) );
				
				NodeList roleReferences = (NodeList) xpath.evaluate( "RoleRef", element, XPathConstants.NODESET );
				RoleManager roleManager = XmlSecurityManager.this.getRoleManager();
				for ( int i=0; i<roleReferences.getLength(); i++ ) {
					Element node = (Element) roleReferences.item( i );
					user.addRole( roleManager.selectRoleById( Integer.parseInt( node.getAttribute( "id" ) ) ) );
				}
				
				return user;
			} catch ( XPathExpressionException exception ) {
				throw new SecurityManagerException( "Cannot select user for login " + login, exception );
			}
		}

		
		@Override public List<User> getUsersByRole( Role role ) throws SecurityManagerException {
			throw new RuntimeException( "Actually not supported" );
		}

		@Override public User insertUser( String login, String password ) throws UserAlreadyRegisteredException, SecurityManagerException {
			if ( login == null ) throw new NullPointerException();
			if ( password == null ) throw new NullPointerException();

			String rawLogin = login;
			login = login.replace( "\"", "&quot;" );
			password = this.encryptPassword( password );
			
			try {
				Element element = (Element) xpath.evaluate( "//User[@login=\"" + login + "\"]" , xmlDocument, XPathConstants.NODE );
				if ( element != null ) throw new UserAlreadyRegisteredException( "User login already registered" );
				
				int identifier = 1 + Integer.parseInt( (String) xpath.evaluate( "//User[last()]/@id" , xmlDocument, XPathConstants.STRING ) );
				
				element = (Element) xpath.evaluate( "//Users" , xmlDocument, XPathConstants.NODE );
				Text textNode = xmlDocument.createTextNode( "\t" );
				element.appendChild( textNode );
				Element roleElement = xmlDocument.createElement( "User" );
				roleElement.setAttribute( "id", "" + identifier );
				roleElement.setAttribute( "login", rawLogin );
				roleElement.setAttribute( "password", password );
				roleElement.setAttribute( "connectionNumber", "0" );
				roleElement.setAttribute( "isDisabled", "false" );
				roleElement.setAttribute( "consecutiveErrors", "0" );
				element.appendChild( roleElement );
				textNode = xmlDocument.createTextNode( "\r\n\t" );
				element.appendChild( textNode );
				saveXmlDocument();
				
				UserImpl user = new UserImpl( XmlSecurityManager.this, identifier, rawLogin, password );
				user.setIdentifier( identifier );
				
				return user;				
			} catch ( XPathExpressionException exception ) {
				throw new SecurityManagerException( "Cannot insert new user", exception );
			}
		}

		@Override public void updateUser( User user ) throws SecurityManagerException {
			if ( user == null ) throw new NullPointerException();
			try {
				Element element = (Element) xpath.evaluate( "//User[@id='" + user.getIdentifier() + "']" , xmlDocument, XPathConstants.NODE );
				element.setAttribute( "login", user.getLogin() );
				element.setAttribute( "password", ( (UserImpl) user ).getPassword() );
				element.setAttribute( "connectionNumber", "" + user.getConnectionNumber() );
				element.setAttribute( "lastConnection", "" + user.getLastConnection().getTime() );
				element.setAttribute( "consecutiveErrors", "" + user.getConsecutiveErrors() );
				element.setAttribute( "isDisabled", "" + user.isDisabled() );

				// Remove all roleRef tags
				while ( element.hasChildNodes() ) {
					element.removeChild( element.getFirstChild() );
				}
				
				// Add new roleRef tags
				for ( Role role : user.getRoles() ) {
					Text textNode = xmlDocument.createTextNode( "\r\n\t\t" );
					element.appendChild( textNode );
					Element roleElement = xmlDocument.createElement( "RoleRef" );
					roleElement.setAttribute( "id", "" + role.getIdentifier() );
					element.appendChild( roleElement );
				}
				Text textNode = xmlDocument.createTextNode( "\r\n\t" );
				element.appendChild( textNode );
				
				// Commit database updates
				saveXmlDocument();
				
			} catch ( XPathExpressionException exception ) {
				throw new SecurityException( "Cannot udate user data", exception );
			}
		}

		@Override public void deleteUser( User user ) throws SecurityManagerException {
			if ( user == null ) throw new NullPointerException();
			try {
				Element parentElement = (Element) xpath.evaluate( "//Users" , xmlDocument, XPathConstants.NODE );
				Element element = (Element) xpath.evaluate( "//User[@id='" + user.getIdentifier() + "']" , xmlDocument, XPathConstants.NODE );
				if ( element == null ) throw new SecurityManagerException( "User " + user.getLogin() + " not found in XML security database" );
				Node nextSiblingNode = element.getNextSibling();
				
				parentElement.removeChild( element );
				if ( nextSiblingNode != null ) parentElement.removeChild( nextSiblingNode );
			} catch ( XPathExpressionException exception ) {
				throw new SecurityManagerException( "Can't delete the specified user", exception );
			}
		}

		@Override public String encryptPassword( String clearPassword ) throws SecurityManagerException {
			if ( clearPassword == null ) throw new NullPointerException();
			try {
				byte[] unicodeValue = clearPassword.getBytes( "utf-16" );
	            MessageDigest messageDigest = MessageDigest.getInstance( "SHA1" );
	            messageDigest.update( unicodeValue );
	            byte[] encodedPasswordBuffer = messageDigest.digest();
	            return XmlSecurityManager.encryptedKeyTostring( encodedPasswordBuffer );
			} catch ( Exception exception ) {
				throw new SecurityManagerException( "Cannot encode password", exception );
			}
		}
		
	}
	
	private class XmlRoleManager implements RoleManager {

		@Override public Role selectRoleById( int roleIdentifier ) throws SecurityManagerException {
			try {
				Element element = (Element) xpath.evaluate( "//Role[@id=" + roleIdentifier + "]" , xmlDocument, XPathConstants.NODE );
				if ( element == null ) {
					throw new SecurityManagerException( "Role identifier " + roleIdentifier + " not found" );
				}
				return new RoleImpl( roleIdentifier, element.getAttribute( "roleName" ) );
			} catch ( XPathExpressionException exception ) {
				throw new SecurityManagerException( "Cannot select role for identifier " + roleIdentifier, exception );
			}
		}

		@Override public Role selectRoleByName( String roleName ) throws SecurityManagerException {
			try {
				Element element = (Element) xpath.evaluate( "//Role[@roleName='" + roleName + "']" , xmlDocument, XPathConstants.NODE );
				if ( element == null ) {
					throw new SecurityManagerException( "Role name " + roleName + " not found" );
				}
				return new RoleImpl( Integer.parseInt( element.getAttribute( "id" ) ), roleName );
			} catch ( XPathExpressionException exception ) {
				throw new SecurityManagerException( "Cannot select role for name " + roleName, exception );
			}
		}

		@Override public Role insertRole( String roleName ) throws SecurityManagerException, RoleAlreadyRegisteredException {
			try {
				Element element = (Element) xpath.evaluate( "//Role[@roleName='" + roleName + "']" , xmlDocument, XPathConstants.NODE );
				if ( element != null ) throw new RoleAlreadyRegisteredException( "Role name already registered" );				
				
				element = (Element) xpath.evaluate( "//Roles" , xmlDocument, XPathConstants.NODE );
				int newId = 1 + Integer.parseInt( (String) xpath.evaluate( "//Role[last()]/@id" , xmlDocument, XPathConstants.STRING ) );
				Text textNode = xmlDocument.createTextNode( "\t" );
				element.appendChild( textNode );
				Element roleElement = xmlDocument.createElement( "Role" );
				roleElement.setAttribute( "id", "" + newId );
				roleElement.setAttribute( "roleName", roleName );
				element.appendChild( roleElement );
				textNode = xmlDocument.createTextNode( "\r\n\t" );
				element.appendChild( textNode );
							
				saveXmlDocument();
				return new RoleImpl( newId, roleName );
			} catch ( XPathException exception ) {
				throw new SecurityManagerException( "Can't insert the specified role", exception );
			}
		}

		@Override public void updateRole( Role role ) throws SecurityManagerException {
			if ( role == null ) throw new NullPointerException();
			try {
				Element element = (Element) xpath.evaluate( "//Role[@id='" + role.getIdentifier() + "']" , xmlDocument, XPathConstants.NODE );
				if ( element == null ) throw new SecurityManagerException( "Role " + role.getRoleName() + " not found in XML security database" );
				element.setAttribute( "roleName", role.getRoleName() );
				saveXmlDocument();
			} catch ( Exception exception ) {
				throw new SecurityManagerException( "Cannot update role " + role.getIdentifier(), exception );
			}
		}

		@Override public void deleteRole( Role role ) throws SecurityManagerException {
			if ( role == null ) throw new NullPointerException();
			try {
				Element parentElement = (Element) xpath.evaluate( "//Roles" , xmlDocument, XPathConstants.NODE );
				Element element = (Element) xpath.evaluate( "//Role[@id='" + role.getIdentifier() + "']" , xmlDocument, XPathConstants.NODE );
				if ( element == null ) throw new SecurityManagerException( "Role " + role.getRoleName() + " not found in XML security database" );
				Node nextSiblingNode = element.getNextSibling();
				
				parentElement.removeChild( element );
				if ( nextSiblingNode != null ) parentElement.removeChild( nextSiblingNode );
			} catch ( XPathException exception ) {
				throw new SecurityManagerException( "Can't delete the specified role", exception );
			}

		}
	}

	private void saveXmlDocument() throws SecurityManagerException {
		try {
			DOMImplementationLS domImplLS = (DOMImplementationLS) this.xmlDocument.getImplementation().getFeature( "LS", "3.0" );
			LSOutput outputLS = domImplLS.createLSOutput();
			outputLS.setByteStream( new FileOutputStream( this.xmlFilename ) );
			LSSerializer serializer = domImplLS.createLSSerializer();
			try {
				serializer.getDomConfig().setParameter( "format-pretty-print", true );
			} catch ( Exception exception ) {
				/* NOT ACTUALY SUPPORTED */ 
			}
			serializer.write( this.xmlDocument, outputLS );
			outputLS.getByteStream().close();
		} catch ( Exception exception ) {
			throw new SecurityManagerException( "Cannot save security XML file", exception );
		}
	}

	/**
	 * Encode an encrypted key to a readable string.
	 * @param bytes	The input encrypted key
	 * @return The readable string.
	 */
	private static String encryptedKeyTostring( byte[] bytes ) {
		final String digitTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	    StringBuilder buffer = new StringBuilder();
	    int i = 0;
	    byte pos;
	    
	    for ( i = 0; i < bytes.length - bytes.length % 3; i += 3 ) {
	        pos = (byte) ( bytes[i] >> 2 & 63 );
	        buffer.append( digitTable.charAt( pos ) );
	        pos = (byte) ( ( ( bytes[i] & 3 ) << 4 ) + ( bytes[i + 1] >> 4 & 15 ) );
	        buffer.append( digitTable.charAt( pos ) );
	        pos = (byte) ( ( ( bytes[i + 1] & 15 ) << 2 ) + ( bytes[i + 2] >> 6 & 3 ) );
	        buffer.append( digitTable.charAt( pos ) );
	        pos = (byte) ( bytes[i + 2] & 63 );
	        buffer.append( digitTable.charAt( pos ) );
	    }
	    
	    if ( bytes.length % 3 != 0 ) {
	        if ( bytes.length % 3 == 2 ) {
	            pos = (byte) ( bytes[i] >> 2 & 63 );
	            buffer.append( digitTable.charAt( pos ) );
	            pos = (byte) ( ( ( bytes[i] & 3 ) << 4 ) + ( bytes[i + 1] >> 4 & 15 ) );
	            buffer.append( digitTable.charAt( pos ) );
	            pos = (byte) ( ( bytes[i + 1] & 15 ) << 2 );
	            buffer.append( digitTable.charAt( pos ) );
	            buffer.append( "*" );
	        } else if ( bytes.length % 3 == 1 ) {
	            pos = (byte) ( bytes[i] >> 2 & 63 );
	            buffer.append( digitTable.charAt( pos ) );
	            pos = (byte) ( ( bytes[i] & 3 ) << 4 );
	            buffer.append( digitTable.charAt( pos ) );
	            buffer.append( "**" );
	        }
	    }
	    return buffer.toString();
	}

}
