package fr.koor.utility;

/** 
 * The interface DataSource defines strings used for JDBC database connections.
 * There are four strings representing driver name, connection url, login and password.
 * 
 * @author Infini Software - Dominique Liard
 * @since 0.3.6
 */
public interface DataSource {
	
	/**
	 * Returns the JDBC driver class name associated to this data source.
	 * @return The JDBC driver class name.
	 */
	public String getDriverClassName();
	
	/**
	 * Returns the JDBC connection url. This URL contains all informations to locate the database used by the security
	 * manager (database host, database port, database name, ...).
	 * @return The JDBC connection URL
	 */
	public String getConnectionURL();
	
	/**
	 * Returns the login used for security database connection.
	 * @return The login.
	 */
	public String getLogin();
	
	/**
	 * Returns the password used for security database connection.
	 * @return The password.
	 */
	public String getPassword();
}