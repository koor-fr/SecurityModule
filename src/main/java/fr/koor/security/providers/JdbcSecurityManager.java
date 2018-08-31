package fr.koor.security.providers;

import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

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
import fr.koor.utility.DataSource;


/** 
 * <p>
 *     This security manager (see interface fr.koor.security.SercurityManager)  use a relational database to store the security informations.
 *     Actually two relational database management systems (also known as RDBMS) are supported : Apache Derby ou Sun MySql. In future versions, other RDBMS
 * 	   will be supported. The JDBC API is used by this implementation to provide RDBMS access.
 * </p>
 * 
 * <p>
 *     To specify the used RDBMS, you must pass a data source that describe the JDBC connection. A data source is defined by the JdbcSecurityManager.DataSource.
 * </p>
 * 
 * @see fr.koor.security.SecurityManager
 * @see fr.koor.utility.utilities.jdbc.DataSource
 * 
 * @author Infini Software - Dominique Liard
 * @since 0.3.6
 */
public class JdbcSecurityManager implements fr.koor.security.SecurityManager {

	private DataSource dataSource;
	private Connection jdbcConnection;


	private UserManager userManager = new JdbcUserManager();
	private RoleManager roleManager = new JdbcRoleManager();
		
	/**
	 * This constructor produces an instance of security manager that has based on a JDBC data source.
	 * 
	 * @param dataSource					The JDBC data source
	 * 
	 * @throws SecurityManagerException		Thrown if the system cannot connect to the database. 
	 */
	public JdbcSecurityManager( DataSource dataSource ) throws SecurityManagerException {
		if ( dataSource == null ) throw new NullPointerException();
		this.dataSource = dataSource;
		try {
			Class.forName( this.dataSource.getDriverClassName() );
		} catch ( Throwable throwable ) {
			throw new SecurityManagerException( "Cannot instanciate security manager", throwable );
		}
	
		this.openSession();
	}
	
	/**
	 * This constructor produces an instance of security manager that has based on a JDBC connection.
	 * 
	 * @param connection					The JDBC connection to use.
	 * @since 0.4.0
	 */
	public JdbcSecurityManager( Connection connection ) {
		if ( connection == null ) throw new NullPointerException();
		this.jdbcConnection = connection;
		this.dataSource = null;
	}
	
	
	@SuppressWarnings( "unused" )
	private JdbcSecurityManager() {
		// Just for mocked instanciation: do not remove.			It's used in EllipseGenerator
	}
	
	
	@Override
	public void openSession() throws SecurityManagerException {
		try {
		    this.jdbcConnection = DriverManager.getConnection(
				this.dataSource.getConnectionURL(), this.dataSource.getLogin(), this.dataSource.getPassword()
			);
			this.constructTablesIfNotExists();
		} catch ( Throwable throwable ) {
			throw new SecurityManagerException( "Cannot open security session", throwable );
		}
	}

	
	@Override public void close() throws SecurityManagerException {
		try {
			this.jdbcConnection.close();
			this.jdbcConnection = null;
		} catch ( Throwable throwable ) {
			throw new SecurityManagerException( "Cannot close security session", throwable );
		}
	}


	@Override public RoleManager getRoleManager() {
		return this.roleManager;
	}


	@Override public UserManager getUserManager() {
		return this.userManager;
	}

	/**
	 * Check if each table exists. If a table not exists, the manager create it. 
	 */
	private void constructTablesIfNotExists() throws Exception {
		DatabaseMetaData metaData = this.jdbcConnection.getMetaData();
		if ( metaData.supportsANSI92EntryLevelSQL() == false ) {
			throw new SQLException( "The JdbcSecurityManager class requires a JDBC driver that supports SQL ANSI 92. " +
					"DatabaseMetaData.supportsANSI92EntryLevelSQL returns false." );
		}
				
		ResultSet rsTables = metaData.getTables( null, null, "T_ROLES", new String[] { "TABLE" } );
		if ( rsTables.next() == false ) {
			Statement stCreateTRoles = this.jdbcConnection.createStatement();
			stCreateTRoles.executeUpdate( this.jdbcConnection.nativeSQL( CREATE_T_ROLES_STATEMENT ) );
			stCreateTRoles.executeUpdate( "INSERT INTO T_ROLES VALUES (1, 'admin')" );
		}
		rsTables.close();
		
		rsTables = metaData.getTables( null, null, "T_USERS", new String[] { "TABLE" } );
		if ( rsTables.next() == false ) {
			Statement stCreateTUsers = this.jdbcConnection.createStatement();
			String updateStatement = CREATE_T_USERS_STATEMENT;
			if ( this.jdbcConnection.getMetaData().getDriverName().indexOf( "Derby" ) > -1 ) {
				updateStatement = updateStatement.replace( "datetime", "timestamp" );
			}
			stCreateTUsers.executeUpdate( this.jdbcConnection.nativeSQL( updateStatement ) );
			stCreateTUsers.executeUpdate( "INSERT INTO T_USERS VALUES( 1, 'root', '" + userManager.encryptPassword( "admin" ) + "' , 0, " + this.toDBString( new Date() ) + ",0 ,0, 'root', 'administrator', '' )" );
		}
		rsTables.close();
		
		rsTables = metaData.getTables( null, null, "T_USER_ROLES", new String[] { "TABLE" } );
		if ( rsTables.next() == false ) {
			Statement stCreateTUserRoles = this.jdbcConnection.createStatement();
			stCreateTUserRoles.executeUpdate( this.jdbcConnection.nativeSQL( CREATE_T_USER_ROLES_STATEMENT ) );
			stCreateTUserRoles.executeUpdate( "INSERT INTO T_USER_ROLES VALUES( 1, 1 )" );
		}
		rsTables.close();
	}
	
	
	/** 
	 * JDBC implementation for the RoleManager interface.
	 *  
	 * @author Dominique Liard
	 * @since 0.3.6
	 */
	private class JdbcRoleManager implements RoleManager {

		@Override public void deleteRole( Role role ) throws SecurityManagerException {
			if ( role == null ) throw new NullPointerException();
			try {
				String strSql = "DELETE FROM T_ROLES WHERE IdRole=" + role.getIdentifier();
				JdbcSecurityManager.this.getConnection().createStatement().executeUpdate( strSql );
			} catch ( SQLException exception ) {
				throw new SecurityManagerException( "Can't delete the specified role", exception );
			}
		}

		@Override public synchronized Role insertRole( String roleName ) throws SecurityManagerException {
			if ( roleName == null ) throw new NullPointerException();

			try {
				String strSql = "SELECT IdRole FROM T_ROLES WHERE RoleName=?";
				PreparedStatement stRole = JdbcSecurityManager.this.getConnection().prepareStatement( strSql );
				stRole.setString( 1, roleName );
				ResultSet rsRole = stRole.executeQuery();
				try {
					if ( rsRole.next() ) throw new RoleAlreadyRegisteredException( "Role name already registered for " + roleName );
				} finally { 
					rsRole.close();
				}
			} catch ( SQLException exception ) {
				throw new SecurityManagerException( "Can't check the role existance", exception );
			}
				
			try {
				int primaryKey = JdbcSecurityManager.this.getNextAvailablePrimaryKey( "T_ROLES", "IdRole" );
				String strSql = "INSERT INTO T_ROLES VALUES (" + primaryKey + ", '" + roleName.replace( "'", "''" ) + "')";
				JdbcSecurityManager.this.getConnection().createStatement().executeUpdate( strSql );
				return new RoleImpl( primaryKey, roleName );
			} catch ( Exception exception ) {
				throw new SecurityManagerException( "Can't insert the specified role", exception );
			}
		}
		

		@Override public Role selectRoleById( int roleIdentifier ) throws SecurityManagerException {
			try {
				String strSql = "SELECT * FROM T_ROLES WHERE IdRole=" + roleIdentifier;
				ResultSet rsRole = JdbcSecurityManager.this.getConnection().createStatement().executeQuery( strSql );
				if ( rsRole.next() ) {
					return new RoleImpl( roleIdentifier, rsRole.getString( 2 ) );
				}
				
				throw new SecurityManagerException( "Role identifier " + roleIdentifier + " not found" );
			} catch ( Exception exception ) {
				throw new SecurityManagerException( "Cannot select role for identifier " + roleIdentifier, exception );
			}
		}
		

		@Override public Role selectRoleByName( String roleName ) throws SecurityManagerException {
			if ( roleName == null ) throw new NullPointerException();
			String strSql = "SELECT * FROM T_ROLES WHERE RoleName=?";
			try ( PreparedStatement statement = JdbcSecurityManager.this.getConnection().prepareStatement( strSql ) ) {
				statement.setString( 1, roleName );
				try ( ResultSet rsRole = statement.executeQuery() ) {
					if ( rsRole.next() ) {
						Role role = new RoleImpl( rsRole.getInt( 1 ), roleName );
						rsRole.close();
						return role;
					}
				}
				
				throw new SecurityManagerException( "Role " + roleName + " not found" );
			} catch ( Exception exception ) {
				throw new SecurityManagerException( "Cannot select role " + roleName, exception );
			}
		}

		@Override public void updateRole( Role role ) throws SecurityManagerException {
			if ( role == null ) throw new NullPointerException();
			try {
				String strSql = "UPDATE T_ROLES SET RoleName=? WHERE IdRole=?";
				PreparedStatement statement = JdbcSecurityManager.this.getConnection().prepareStatement( strSql );
				statement.setString( 1, role.getRoleName() );
				statement.setInt( 2, role.getIdentifier() );
				statement.executeUpdate();
			} catch ( Exception exception ) {
				throw new SecurityManagerException( "Cannot update role " + role.getIdentifier(), exception );
			}
		}			
	}
	
	
	/** 
	 * JDBC implementation for the UserManager interface.
	 *  
	 * @author Dominique Liard
	 * @since 0.3.6
	 */
	private class JdbcUserManager implements UserManager {

		@Override public User checkCredentials( String userLogin, String userPassword )
								throws AccountDisabledException, BadCredentialsException {
			if ( userLogin == null ) throw new NullPointerException();
			if ( userPassword == null ) throw new NullPointerException();

			try {
				userPassword = this.encryptPassword( userPassword );
				//System.out.println( userPassword );
				
				String strSql = "SELECT * FROM T_USERS WHERE Login=? and  Password=?";
				PreparedStatement prepStatement = JdbcSecurityManager.this.getConnection().prepareStatement( strSql );
				prepStatement.setString( 1, userLogin );
				prepStatement.setString( 2, userPassword );
				
				try ( ResultSet rsCredentials = prepStatement.executeQuery() ) {
					if ( rsCredentials.next() ) {
						// User informations update
						
						int identifier = rsCredentials.getInt( "idUser" );
						int connectionNumber =  rsCredentials.getInt( "connectionNumber" ) + 1;
						Date lastConnection = new Date();
						int consecutiveError = rsCredentials.getInt( "consecutiveError" );
						boolean isDisabled = rsCredentials.getBoolean( "isDisabled" );
						String firstName = rsCredentials.getString( "firstName" );
						String lastName = rsCredentials.getString( "lastName" );
						String email = rsCredentials.getString( "email" );
						
						strSql = "UPDATE T_USERS SET ConnectionNumber=" + connectionNumber + ", LastConnection=" + toDBString( lastConnection )
							   + " WHERE IdUser=" + identifier;
						Statement statement = JdbcSecurityManager.this.getConnection().createStatement();
						statement.executeUpdate( strSql );				
						
						if ( isDisabled ) {
							throw new AccountDisabledException( "Account is disabled" );
						} else {
							if ( consecutiveError != 0 ){
								strSql = "UPDATE T_USERS SET ConsecutiveError = 0 WHERE IdUser=" + identifier;
								statement.executeUpdate( strSql );
								consecutiveError = 0;
							}
						}
					
						UserImpl user = new UserImpl( JdbcSecurityManager.this, identifier, userLogin, userPassword );
						user.setConnectionNumber( connectionNumber );
						user.setLastConnection( lastConnection );
						user.setConsecutiveErrors( consecutiveError );
						user.setDisabled( isDisabled );
						user.setFirstName( firstName );
						user.setLastName( lastName );
						user.setEmail( email );
						
						// Associated roles loading
						RoleManager roleManager = JdbcSecurityManager.this.getRoleManager();
						strSql = "SELECT IdRole FROM T_USER_ROLES WHERE IdUser=" + user.getIdentifier();
						ResultSet rsRoles = statement.executeQuery( strSql );
						while ( rsRoles.next() ) { 
							user.addRole( roleManager.selectRoleById( rsRoles.getInt( 1 ) ) );
						}
						rsRoles.close();
						
						return user;
					}
				}
			} catch ( AccountDisabledException exception ) {
				throw exception;	
			} catch ( Exception exception ) {
				throw new BadCredentialsException( "Can't check credentials", exception );
			}

			try {
				String strSql = "SELECT * FROM T_USERS WHERE Login=?";
				PreparedStatement prepStatement = JdbcSecurityManager.this.getConnection().prepareStatement( strSql );
				prepStatement.setString( 1, userLogin );
				ResultSet rs = prepStatement.executeQuery();
				if ( rs.next() ) {
					int idUser = rs.getInt( 1 );
					boolean forceDisabling = rs.getInt( 6 ) == 2; 
					rs.close();
					
					strSql = "UPDATE T_USERS SET ConsecutiveError=ConsecutiveError+1 WHERE IdUser=" + idUser;
					Statement statement = JdbcSecurityManager.this.getConnection().createStatement();
					statement.executeUpdate( strSql );
					
					if ( forceDisabling ) {
						strSql = "UPDATE T_USERS SET IsDisabled = 1 WHERE IdUser=" + idUser;
						statement.executeUpdate( strSql );
						throw new AccountDisabledException( "Account is disabled" );
					}
				} else {
					rs.close();
				}
			} catch ( SQLException exception ) {
				exception.printStackTrace();
				throw new BadCredentialsException( "Your identity is rejected" );
			}
			
			throw new BadCredentialsException( "Your identity is rejected" );
		}
		
		@Override public User getUserById( int idUser ) throws SecurityManagerException {
			try {
				String strSql = "SELECT * FROM T_USERS WHERE IdUser=" + idUser;
				Statement statement = JdbcSecurityManager.this.getConnection().createStatement();
				ResultSet rsCredentials = statement.executeQuery( strSql );

				try {
					if ( rsCredentials.next() ) {
						// User informations update

						String userLogin =  rsCredentials.getString( 2 );
						String userPassword =  rsCredentials.getString( 3 );
						
						UserImpl user = new UserImpl( JdbcSecurityManager.this, idUser, userLogin, userPassword );
						user.setFirstName( rsCredentials.getString( "firstName" ) );
						user.setLastName( rsCredentials.getString( "lastName" ) );
						user.setEmail( rsCredentials.getString( "email" ) );
						
						// Associated roles loading
						RoleManager roleManager = JdbcSecurityManager.this.getRoleManager();
						strSql = "SELECT IdRole FROM T_USER_ROLES WHERE IdUser=" + user.getIdentifier();
						ResultSet rsRoles = statement.executeQuery( strSql );
						while ( rsRoles.next() ) { 
							user.addRole( roleManager.selectRoleById( rsRoles.getInt( 1 ) ) );
						}
						rsRoles.close();

						return user;
					}
				} finally {
					rsCredentials.close();
				}	
			} catch ( Exception exception ) {
				exception.printStackTrace();
				//throw new BadCredentialsException( "Can't check credentials", exception );
			}
			return null;
		}

		@Override public User getUserByLogin( String login ) throws SecurityManagerException {
			try {
				String strSql = "SELECT * FROM T_USERS WHERE login=?";
				try ( PreparedStatement statement = JdbcSecurityManager.this.getConnection().prepareStatement( strSql ) ) {
					statement.setString( 1, login );
	
					try ( ResultSet rsCredentials = statement.executeQuery() )  {
						if ( rsCredentials.next() ) {
							// User informations update
							int identifier =  rsCredentials.getInt( 1 );
							String userPassword =  rsCredentials.getString( 3 );
							
							UserImpl user = new UserImpl( JdbcSecurityManager.this, identifier, login, userPassword );
							user.setFirstName( rsCredentials.getString( "firstName" ) );
							user.setLastName( rsCredentials.getString( "lastName" ) );
							user.setEmail( rsCredentials.getString( "email" ) );
							
							// Associated roles loading
							RoleManager roleManager = JdbcSecurityManager.this.getRoleManager();
							strSql = "SELECT IdRole FROM T_USER_ROLES WHERE IdUser=" + user.getIdentifier();
							Statement stRoles = JdbcSecurityManager.this.getConnection().createStatement();
							ResultSet rsRoles = stRoles.executeQuery( strSql );
							while ( rsRoles.next() ) { 
								user.addRole( roleManager.selectRoleById( rsRoles.getInt( 1 ) ) );
							}
							rsRoles.close();
							stRoles.close();
	
							return user;
						}
					}
				}	
			} catch ( Exception exception ) {
				exception.printStackTrace();
				//throw new BadCredentialsException( "Can't check credentials", exception );
			}
			return null;
		}

		@Override public List<User> getUsersByRole( Role role ) throws SecurityManagerException {
			String strSql = "SELECT tu.* FROM T_USERS tu INNER JOIN T_USER_ROLES tur ON tu.idUser = tur.idUser WHERE tur.idRole=?";
			List<User> users = new ArrayList<>();
			
			try ( PreparedStatement statement = JdbcSecurityManager.this.getConnection().prepareStatement( strSql ) )  {
				statement.setInt( 1, role.getIdentifier() );
				try ( ResultSet rsUsers = statement.executeQuery() ) {
					while ( rsUsers.next() ) {

						// User construction
						UserImpl user = new UserImpl( JdbcSecurityManager.this, rsUsers.getInt( "idUser" ), rsUsers.getString( "login" ), rsUsers.getString( "password" ) );
						user.setConnectionNumber( rsUsers.getInt( "connectionNumber" ) );
						user.setLastConnection( rsUsers.getTimestamp( "lastConnection" ) );
						user.setConsecutiveErrors( rsUsers.getInt( "consecutiveError" ) );
						user.setDisabled( rsUsers.getBoolean( "isDisabled" ) );
						user.setFirstName( rsUsers.getString( "firstName" ) );
						user.setLastName( rsUsers.getString( "lastName" ) );
						user.setEmail( rsUsers.getString( "email" ) );
						
						// Associated roles loading
						RoleManager roleManager = JdbcSecurityManager.this.getRoleManager();
						strSql = "SELECT IdRole FROM T_USER_ROLES WHERE IdUser=" + user.getIdentifier();
						try ( Statement stRoles = JdbcSecurityManager.this.getConnection().createStatement() ) {
							try ( ResultSet rsRoles = stRoles.executeQuery( strSql ) ) {
								while ( rsRoles.next() ) { 
									user.addRole( roleManager.selectRoleById( rsRoles.getInt( 1 ) ) );
								}
							}
						}
						users.add( user );
					}
				}
			} catch ( Exception exception ) {
				exception.printStackTrace();
				//throw new BadCredentialsException( "Can't check credentials", exception );
			}
			
			return users;
		}
		
		
		@Override public void deleteUser( User user ) throws SecurityManagerException {
			if ( user == null ) throw new NullPointerException();
			try {
				Statement statement = JdbcSecurityManager.this.getConnection().createStatement();
				
				// Associated role deletions
				String strSql = "DELETE FROM T_USER_ROLES WHERE IdUser=" + user.getIdentifier();
				statement.executeUpdate( strSql );


				// User deletion
				strSql = "DELETE FROM T_USERS WHERE IdUser=" + user.getIdentifier();
				statement.executeUpdate( strSql );
			} catch ( SQLException exception ) {
				throw new SecurityManagerException( "Can't delete the specified user", exception );
			}
		}

		@Override public synchronized User insertUser( String login, String password ) throws SecurityManagerException {
			if ( login == null ) throw new NullPointerException();
			if ( password == null ) throw new NullPointerException();

			Connection connection = JdbcSecurityManager.this.getConnection();

			String strSql = "SELECT IdUser FROM T_USERS WHERE Login=?";
			try ( PreparedStatement stUser = connection.prepareStatement( strSql ) ) {
				stUser.setString( 1, login );
				ResultSet rsUser = stUser.executeQuery();
				try {
					if ( rsUser.next() ) throw new UserAlreadyRegisteredException( "User login already registered" );
				} finally { 
					rsUser.close();
				}
				
				int primaryKey = JdbcSecurityManager.this.getNextAvailablePrimaryKey( "T_USERS", "IdUser" );
				
//				if ( connection.getMetaData().getDatabaseProductName().equalsIgnoreCase( "Microsoft SQL Server" ) ) {
//					connection.createStatement().executeUpdate( "SET IDENTITY_INSERT T_USERS ON" );
//				}
				
				strSql = "INSERT INTO T_USERS VALUES ( ?, ?, ?, 0, null, 0, 0, '', '', '' )";
				try ( PreparedStatement statement = connection.prepareStatement(  strSql ) ) {
					statement.setInt( 1, primaryKey );
					statement.setString( 2, login );
					statement.setString( 3, this.encryptPassword( password ) );
					statement.executeUpdate();
					
					UserImpl user = new UserImpl( JdbcSecurityManager.this, primaryKey, login, this.encryptPassword( password ) );
					user.setIdentifier( primaryKey );
					
					return user;
				}
			} catch ( SQLException exception ) {
				throw new SecurityManagerException( "Cannot insert new user", exception );
			}
		}

		@Override public void updateUser( User user ) throws SecurityManagerException {
			if ( user == null ) throw new NullPointerException();
			// Update the T_Users record
			String strSql = "UPDATE T_USERS SET Login=?, Password=?, ConnectionNumber=?, LastConnection=?, FirstName=?, LastName=?, Email=? WHERE IdUser=?";
			try ( PreparedStatement prepStatement = JdbcSecurityManager.this.getConnection().prepareStatement( strSql ) ) {
				prepStatement.setString( 1, user.getLogin() );
				prepStatement.setString( 2, ( (UserImpl) user ).getPassword() );
				prepStatement.setInt( 3, user.getConnectionNumber() );
				prepStatement.setDate( 4, new java.sql.Date( user.getLastConnection().getTime() ) );
				prepStatement.setString( 5, user.getFirstName() );
				prepStatement.setString( 6, user.getLastName() );
				prepStatement.setString( 7, user.getEmail() );
				prepStatement.setInt( 8, user.getIdentifier() );
				prepStatement.executeUpdate();				

				// Delete and recreate the T_USER_ROLES records
				strSql = "DELETE FROM T_USER_ROLES WHERE IdUser=" + user.getIdentifier();
				try ( Statement statement = JdbcSecurityManager.this.getConnection().createStatement() ) {
					statement.executeUpdate( strSql );
					for ( Role role : user.getRoles() ) {
						strSql = "INSERT INTO T_USER_ROLES (IdUser, IdRole) VALUES (" +  user.getIdentifier() + "," + role.getIdentifier() + ")";
						statement.executeUpdate( strSql );
					}
				}
			} catch ( SQLException exception ) {
				throw new SecurityException( "Cannot udate user data", exception );
			}
		}
		
		@Override public String encryptPassword( String clearPassword ) throws SecurityManagerException {
			if ( clearPassword == null ) throw new NullPointerException();
			try {
				byte[] unicodeValue = clearPassword.getBytes( "utf-16" );
	            MessageDigest messageDigest = MessageDigest.getInstance( "SHA1" );
	            messageDigest.update( unicodeValue );
	            byte[] encodedPasswordBuffer = messageDigest.digest();
	            return JdbcSecurityManager.encryptedKeyTostring( encodedPasswordBuffer );
			} catch ( Exception exception ) {
				throw new SecurityManagerException( "Cannot encode password", exception );
			}
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

	
	/**
	 * Return the underlying JDBC connection to the database.
	 * 
	 * @return The underlying connection.
	 * @since 0.4.0
	 */
	public Connection getConnection() {
		return this.jdbcConnection;
	}

	
	/**
	 * Returns the next used primary key for the specified table and column.
	 * Caution: the type of the specified column must be compatible with the int java type.
	 *  
	 * @param tableName		The name of the considered table.
	 * @param columnName	The name of the column that contains primary keys.
	 * @return The next used value.
	 * 
	 * @throws SQLException	Thrown if a Sql error is generated.
	 */
	private int getNextAvailablePrimaryKey( String tableName, String columnName ) throws SQLException {
		String strSql = "SELECT max(" + columnName + ") FROM " + tableName ;
		try ( ResultSet rsIdRoles = this.jdbcConnection.createStatement().executeQuery( strSql ) ) {
			int nextIndex = 0;
			if ( rsIdRoles.next() ) nextIndex = rsIdRoles.getInt( 1 ) + 1;
			return nextIndex;
		}
	}

	
	/**
	 * Generate a database well formed date string.
	 * @param lastConnection	The date to convert.
	 * @return The date string.
	 */
	private String toDBString( Date lastConnection ) {
		if ( lastConnection == null ) lastConnection = new Date(); 
		return "'" + new Timestamp( lastConnection.getTime() ).toString() + "'";
	}
	
	private static final String CREATE_T_USERS_STATEMENT =
		"CREATE TABLE T_USERS (" +
		"    IdUser              int PRIMARY KEY," +
		"    Login               varchar(50) UNIQUE NOT NULL," +			
		"    Password            varchar(50) NOT NULL," +
		"    ConnectionNumber    int NOT NULL DEFAULT 0," +
		"    LastConnection      datetime," +
		"	 ConsecutiveError	 int		DEFAULT 0," +
		"	 IsDisabled			 int		DEFAULT 0," +
		"    FirstName           varchar(25) NOT NULL DEFAULT ''," +			
		"    LastName            varchar(25) NOT NULL DEFAULT ''," +			
		"    Email               varchar(50) NOT NULL DEFAULT ''" +			
		")";
	
	private static final String CREATE_T_ROLES_STATEMENT =
		"CREATE TABLE T_ROLES (" +
		"    IdRole              int PRIMARY KEY," +
		"    RoleName            varchar(50) UNIQUE NOT NULL" +
		")";
	
	private static final String CREATE_T_USER_ROLES_STATEMENT = 
		"CREATE TABLE T_USER_ROLES (" +
		"    IdUser              int," +
		"    IdRole              int," +
		"  FOREIGN KEY ( IdUser ) REFERENCES T_USERS( IdUser )," +
		"  FOREIGN KEY ( IdRole ) REFERENCES T_ROLES( IdRole )" +
        ")";		

}
