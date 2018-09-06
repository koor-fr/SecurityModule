package fr.koor.utility;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;


/**
 * This class provides methods to manage the file systems and it's elements (files and directories).
 * 
 * @author Dominique Liard
 * @since 0.1.0
 */
public class FileSystem {

	/**
	 * Check a file (or directory) presence on the FileSystem.
	 * 
	 * @param pathName	Specify the path to check existance.
	 * @return true if the file exists, false otherwise.
	 */
	public static boolean isExisting( String pathName ) {
		return new java.io.File( pathName ).exists();
	}
	
	/**
	 * Returns the last modified time for the considered path.
	 * 
	 * @param pathName	The path.
	 * @return	The timestamp the the last modified time. You can construct a Date object with this timestamp.
	 */
	public static long getLastModifiedTime( String pathName ) {
		return new java.io.File( pathName ).lastModified();
	}
	
	/**
	 * <p>
	 *		Remove the specified directory. If the directory is not empty and the recursive value equals true, all files and
	 * 		subdirectories are removed. Otherwise, an IOException will be thrown.
	 * </p>
	 * <p>
	 * 		<b>Important note</b>: removed files and directories are not moved into the trash. There are definitivly removed.
	 * 		Please, use this method with caution. 
	 * </p>
	 * 
	 * @param pathName	The path of the directory to remove.
	 * @param recursive	Pass true value if you want recursivly removed all containing files and subdirectories.
	 * 					Pass false otherwize. 
	 * 
	 * @throws IOException Thrown if the method can't remove the directory structure.
	 */
	public static void rmdir( String pathName, boolean recursive ) throws IOException {
		if ( FileSystem.isExisting( pathName ) == false ) throw new FileNotFoundException( pathName );
		java.io.File folderFile = new java.io.File( pathName );
		if ( folderFile.isDirectory() == false ) throw new IOException( "Not a directory - " + pathName );
		if ( recursive == false ) {
			if ( folderFile.list().length > 0 ) throw new IOException( "Directory isn't empty" );
			folderFile.delete();			
		} else {
			java.io.File [] entry = folderFile.listFiles();
			for ( java.io.File file : entry ) {
				if ( file.isDirectory() ) {
					FileSystem.rmdir( file.getPath(), true );
				} else {
					file.delete();
				}
			}
			folderFile.delete();			
		}
	}



	
	
	/**
	 * <p>
	 *     Moves or renames the considered file. If the destination file exists, this method cannot finish correctly: instead of, use
	 *     <code>moveOrRename( String sourceName, String destinationName, boolean overwrite )</code> to force replacement.
	 * </p>
	 * 
	 * @param sourceName		The originaly file name.
	 * @param destinationName	The new file name.
	 * 
	 * @throws IOException	Thrown if this methods cannot move or rename the considered file.
	 */
	public static void moveOrRename( String sourceName, String destinationName ) throws IOException {
		FileSystem.moveOrRename( sourceName, destinationName, false );
	}
		
	/**
	 * <p>
	 *     Moves or renames the considered file.
	 * </p>
	 *     
	 * @param sourceName		The originaly file name.
	 * @param destinationName	The new file name.
	 * @param overwrite 		Force the exiting destination file to be replaced.
	 * 
	 * @throws IOException	Thrown if this methods cannot move or rename the considered file.
	 * 
	 * @since 0.4.8
	 */		
	public static void moveOrRename( String sourceName, String destinationName, boolean overwrite ) throws IOException {
		// Temporary implementation: expected no dependencies on java.io package.
		
		java.io.File destinationFile = new File( destinationName );

		if ( destinationFile.isDirectory() ) {
			java.io.File sourceFile = new File( sourceName );
			destinationFile = new java.io.File( destinationName + "/" + sourceFile.getName() );
		}

		try {
			FileSystem.copyFile( sourceName, destinationFile.getCanonicalPath(), overwrite );
			FileSystem.delete( sourceName );
		} catch ( Exception exception ) {
			throw new IOException( "Cannot move or rename " + sourceName + " to " + destinationName, exception );
		}
	}
	
	
	/**
	 * Copies the source file on the destination file. If the destination file already exists, an exception is thrown
	 * and the file is not copied.
	 * 
	 * @param sourceFile		The name of the source file (relative or absolute path names are accepted)
	 * @param destinationFile	The name of the destination file  (relative or absolute path names are accepted)
	 * 
	 * @throws IOException	Thrown if the file cannot be copied or if the file exists.
	 */
	public static void copyFile( String sourceFile, String destinationFile ) throws IOException {
		FileSystem.copyFile( sourceFile, destinationFile, false );
	}
	
	/**
	 * Copies the source file on the destination file. If the overwrite boolean paramater is set to true, and if the
	 * destination file exists, it will be overwriten.
	 * 
	 * @param sourceFile		The name of the source file (relative or absolute path names are accepted)
	 * @param destinationFile	The name of the destination file  (relative or absolute path names are accepted)
	 * @param overwrite			Indicates if the destination file can be overwritten (true) or not (false), if file exists.
	 * 
	 * @throws IOException	Thrown if the file cannot be copied or if the file exists and cannot be overwritten.
	 */
	public static void copyFile( String sourceFile, String destinationFile, boolean overwrite ) throws IOException {
		if ( sourceFile == null ) throw new NullPointerException();
		if ( destinationFile == null ) throw new NullPointerException();
		if ( FileSystem.isExisting( destinationFile ) && overwrite == false ) {
			throw new IOException( "File exists and cannot be overwrited" );
		}

		long length = new java.io.File( sourceFile ).length();
		FileInputStream fis = new FileInputStream( sourceFile );
		byte [] buffer = new byte[ 1024 * 1024 ];
		
		FileOutputStream fos = new FileOutputStream( destinationFile );
		
		while ( length > 0 ) {
			long count = fis.read( buffer );
			fos.write( buffer, 0, (int) count );
			length -= count;
		}
		
		fos.close();
		fis.close();
	}
	

	/**
	 * Copies the source stream content on the destination file.
	 * 
	 * @param is				The input stream that contains data to copy.
	 * @param destinationFile	The name of the destination file  (relative or absolute path names are accepted)
	 * 
	 * @throws IOException	Thrown if the file cannot be copied or if the file exists and cannot be overwritten.
	 */
	public static void copyFile( InputStream is, String destinationFile ) throws IOException {
		if ( is == null ) 			   throw new NullPointerException();
		if ( destinationFile == null ) throw new NullPointerException();
		File file = new File( destinationFile );
		FileOutputStream fos = new FileOutputStream( file );
		try {
			byte[] buf = new byte[8192];
			int len;
			while ( ( len = is.read( buf ) ) >= 0 ) {
				fos.write( buf, 0, len );
			}
		} finally {
			fos.close();
		}
	}	
		
	public static void delete( String filename ) throws IOException {
		new java.io.File( filename ).delete();
	}

	/**
	 * This methode delete recursivly all files contained into the specified folder.
	 * Note that the deleted files are not placed into the Trash.
	 * 
	 * @param folder The folder to deeply delete.
	 */
	public static void delTree( String folder ) {
		java.io.File fileObject = new java.io.File( folder );
		if ( fileObject.isDirectory() ) {
			String [] files = fileObject.list();
			for ( String file : files ) FileSystem.delTree( fileObject.getAbsolutePath() + "/" + file );
		}
		fileObject.delete();
	}
	
	public static void touch( String pathName ) throws IOException {
		java.io.File file = new java.io.File( pathName );
		if ( file.exists() ) {
			file.setLastModified( System.currentTimeMillis() );
		} else {
			new FileOutputStream( file ).close();
		}
	}

	public static String[] list( String folderName ) {
		return new java.io.File( folderName ).list();
	}
	
	//public static File[] listFile( String folderName ) { throw new RuntimeException( "NOT IMPLEMENTED" ); }
	
	
	/**
	 * Checks if a path is contained into another path.
	 * 
	 * @param parentPath	The parent folder path.
	 * @param childPath		The child path to check.
	 * @return	True if <code>childPath</code> is contained into <code>parentPath</code>
	 * 
	 * @exception IOException 			Thrown if <code>contains</code> method cannot check containment.
	 * @exception NullPointerException	Thrown if <code>parentPath</code> or <code>childPath</code> are null. 
	 * 
	 * @since 0.4
	 */
	public static boolean contains( String parentPath, String childPath ) throws IOException {
		if ( parentPath == null ) throw new NullPointerException();
		if ( childPath == null ) throw new NullPointerException();
		
		parentPath = new java.io.File( parentPath ).getCanonicalFile().getAbsolutePath();
		childPath =  new java.io.File( childPath ).getCanonicalFile().getAbsolutePath();
		return childPath.startsWith( parentPath );
	}
	
	/**
	 * Returns the current working directory as string instance.
	 * @return The current working directory.
	 */
	public static String getCurrentWorkingDirectory() {
		return new java.io.File( "." ).getAbsolutePath();
	}
	
	// ...
}
