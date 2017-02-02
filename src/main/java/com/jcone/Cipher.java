package com.jcone;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;

import seed.SeedFile;
import seed.SeedString;

public class Cipher {
	private static String[] algorithm = { "SHA512", "AES256", "SEED128" };

	/**
	 * <pre>
	 * SHA-512 암호화
	 * </pre>
	 *
	 * @date 2016. 10. 10.
	 * @author 장인빈 (inbin@jcone.co.kr)
	 * @param data
	 * @return
	 */
	private static String encryptSHA512(String data) {
		String afterData = "";
		MessageDigest sha;
		try {
			sha = MessageDigest.getInstance("SHA-512");
			sha.update(data.getBytes());
			StringBuffer sb = new StringBuffer();
			for (byte b : sha.digest()) {
				sb.append(Integer.toHexString(0xff & b));
			}
			afterData = sb.toString();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return afterData;
	}

	/**
	 * <pre>
	 * PBEWITHSHA256AND256BITAES 암호화
	 * </pre>
	 *
	 * @date 2016. 10. 11.
	 * @author 장인빈 (inbin@jcone.co.kr)
	 * @param message
	 * @return
	 * @throws IOException
	 */
	private static String PBEStrHighEncript(String message, String key) {
		StandardPBEStringEncryptor pbeEnc = new StandardPBEStringEncryptor();
		pbeEnc.setProvider(new BouncyCastleProvider());
		pbeEnc.setAlgorithm("PBEWITHSHA256AND256BITAES-CBC-BC");
		pbeEnc.setPassword(key);
		return pbeEnc.encrypt(message);
	}

	/**
	 * <pre>
	 * PBEWITHSHA256AND256BITAES 복호화
	 * </pre>
	 *
	 * @date 2016. 10. 11.
	 * @author 장인빈 (inbin@jcone.co.kr)
	 * @param encryptedMessage
	 * @return
	 * @throws IOException
	 */
	private static String PBEStrHighDecrypt(String encryptedMessage, String key) {
		StandardPBEStringEncryptor pbeEnc = new StandardPBEStringEncryptor();
		pbeEnc.setProvider(new BouncyCastleProvider());
		pbeEnc.setAlgorithm("PBEWITHSHA256AND256BITAES-CBC-BC");
		pbeEnc.setPassword(key);
		return pbeEnc.decrypt(encryptedMessage);
	}

	/**
	 * <pre>
	 * Seed128 문자열 암호화
	 * </pre>
	 *
	 * @date 2016. 10. 11.
	 * @author 장인빈 (inbin@jcone.co.kr)
	 * @param file
	 * @param encryptPath
	 */
	private static String seedStringEncrypt(String data, String key) {
		SeedString seed = new SeedString();
		seed.setKey(key.getBytes());
		byte[] encryptStr = seed.encrypt(data);
		return DatatypeConverter.printBase64Binary(encryptStr);
	}

	/**
	 * <pre>
	 * Seed128 문자열 복호화
	 * </pre>
	 *
	 * @date 2016. 10. 11.
	 * @author 장인빈 (inbin@jcone.co.kr)
	 * @param file
	 * @param decryptPath
	 */
	private static String seedStringDecrypt(String encryptData, String key) {
		SeedString seed = new SeedString();
		seed.setKey(key.getBytes());
		byte[] encryptBytes = DatatypeConverter.parseBase64Binary(encryptData);
		return seed.decrypt(encryptBytes);
	}

	/**
	 * <pre>
	 * 문자 단방향 암호화
	 * </pre>
	 *
	 * @date 2016. 10. 12.
	 * @author 장인빈 (inbin@jcone.co.kr)
	 * @param data (암호화할 문자)
	 * @param algorithm (알고리즘 종류)
	 * @return
	 * @throws Exception
	 */
	public static String encryptString(String algorithm, String data) {
		String reStr = null;

		if (algorithm.equals(Cipher.algorithm[0])) {
			reStr = Cipher.encryptSHA512(data);
		}

		return reStr;
	}

	/**
	 * <pre>
	 * 문자 양방향 암호화
	 * </pre>
	 *
	 * @date 2016. 10. 12.
	 * @author 장인빈 (inbin@jcone.co.kr)
	 * @param data (암호화할 문자)
	 * @param algorithm (알고리즘 종류)
	 * @param key (암호키 [AES256은 7자리 이하 문자열, SEED128은 16바이트 문자열])
	 * @return
	 * @throws Exception
	 */
	public static String encryptString(String algorithm, String data, String key) {
		String reStr = null;

		if (algorithm.equals(Cipher.algorithm[1])) {
			reStr = Cipher.PBEStrHighEncript(data, key);

		} else if (algorithm.equals(Cipher.algorithm[2])) {
			reStr = Cipher.seedStringEncrypt(data, key);
		}
		return reStr;
	}

	/**
	 * <pre>
	 * 문자 양방향 복호화
	 * </pre>
	 *
	 * @date 2016. 10. 12.
	 * @author 장인빈 (inbin@jcone.co.kr)
	 * @param encryptData (암호화된 문자)
	 * @param algorithm (알고리즘 종류)
	 * @param key (암호키 [AES256은 7자리 이하 문자열, SEED128은 16바이트 문자열])
	 * @return
	 * @throws Exception
	 */
	public static String decryptString(String algorithm, String encryptData, String key) {
		String reStr = null;

		if (algorithm.equals(Cipher.algorithm[1])) {
			reStr = Cipher.PBEStrHighDecrypt(encryptData, key);

		} else if (algorithm.equals(Cipher.algorithm[2])) {
			reStr = Cipher.seedStringDecrypt(encryptData, key);
		}

		return reStr;
	}

	/**
	 * <pre>
	 * Seed128 파일 암호화
	 * (지정한 경로에 암호화된 파일로 저장)
	 * </pre>
	 *
	 * @date 2016. 10. 11.
	 * @author 장인빈 (inbin@jcone.co.kr)
	 * @param file (암호화할 파일 객체)
	 * @param encryptPath (암호화된 파일 경로 [ex:"C:\\encriptionPath.txt"])
	 * @param key (암호화키 16바이트 문자열)
	 * @throws Exception
	 */
	public static File seedFileEncrypt(File file, String encryptPath, String key) throws Exception {
		SeedFile seed = new SeedFile();
		seed.setKey(key.getBytes());
		return seed.encryptFile(file, encryptPath);
	}

	/**
	 * <pre>
	 * Seed128 파일 복호화
	 * (지정한 경로에 복호화된 파일로 저장)
	 * </pre>
	 *
	 * @date 2016. 10. 11.
	 * @author 장인빈 (inbin@jcone.co.kr)
	 * @param file (복호화할 파일 객체)
	 * @param decryptPath (복호화된 파일 경로 [ex:"C:\\decriptionPath_decript.txt"])
	 * @param key (암호화키 16바이트 문자열)
	 * @throws Exception
	 */
	public static File seedFileDecrypt(File file, String decryptPath, String key) throws Exception {
		SeedFile seed = new SeedFile();
		seed.setKey(key.getBytes());
		return seed.decryptFile(file, decryptPath);
	}

	/**
	 * <pre>
	 * Seed128 파일 암호화
	 * (Write in FileOutputStream from File)
	 * </pre>
	 *
	 * @date 2016. 10. 11.
	 * @author 장인빈 (inbin@jcone.co.kr)
	 * @param in (암호화할 파일스트림)
	 * @param fileLength (암호화할 파일의 크기)
	 * @param encryptionPath (암호화할 경로 [ex:"C:\\encriptionPath.dat"])
	 * @param key (암호화키 16바이트 문자열)
	 * @throws Exception
	 */
	public static OutputStream seedFileEncrypt(File file, OutputStream out, String key) throws Exception {
		SeedFile seed = new SeedFile();
		seed.setKey(key.getBytes());
		return seed.encryptFile(file, out);
	}

	/**
	 * <pre>
	 * Seed128 파일 복호화
	 * (Write in FileOutputStream from File)
	 * </pre>
	 *
	 * @date 2016. 10. 11.
	 * @author 장인빈 (inbin@jcone.co.kr)
	 * @param file (복호화할 파일 객체)
	 * @param out (복호화될 파일스트림)
	 * @param key (암호화키 16바이트 문자열)
	 * @throws Exception
	 */
	public static OutputStream seedFileDecrypt(File file, OutputStream out, String key) throws Exception {
		SeedFile seed = new SeedFile();
		seed.setKey(key.getBytes());
		return seed.decryptFile(file, out);
	}

	/**
	 * <pre>
	 * Seed128 파일 암호화
	 * (Write in FileOutputStream from FileInputStream)
	 * </pre>
	 *
	 * @date 2016. 10. 11.
	 * @author 장인빈 (inbin@jcone.co.kr)
	 * @param in (암호화할 파일스트림)
	 * @param fileLength (암호화할 파일의 크기)
	 * @param out (암호화될 파일스트림)
	 * @param key (암호화키 16바이트 문자열)
	 * @throws Exception
	 */
	public static OutputStream seedFileEncrypt(InputStream in, long fileLength, OutputStream out, String key) throws Exception {
		SeedFile seed = new SeedFile();
		seed.setKey(key.getBytes());
		return seed.encryptFile(in, fileLength, out);
	}

	/**
	 * <pre>
	 * Seed128 파일 복호화
	 * (Write in FileOutputStream from FileInputStream)
	 * </pre>
	 *
	 * @date 2016. 10. 11.
	 * @author 장인빈 (inbin@jcone.co.kr)
	 * @param in (복호화할 파일스트림)
	 * @param fileLength (복호화할 파일의 크기)
	 * @param out (복호화될 파일스트림)
	 * @param key (암호화키 16바이트 문자열)
	 * @throws Exception
	 */
	public static OutputStream seedFileDecrypt(InputStream in, long fileLength, OutputStream out, String key) throws Exception {
		SeedFile seed = new SeedFile();
		seed.setKey(key.getBytes());
		return seed.decryptFile(in, fileLength, out);
	}

	/**
	 * <pre>
	 * Seed128 파일 암호화
	 * (Create File from FileInputStream)
	 * </pre>
	 *
	 * @date 2016. 10. 11.
	 * @author 장인빈 (inbin@jcone.co.kr)
	 * @param in (암호화할 파일스트림)
	 * @param fileLength (암호화할 파일의 크기)
	 * @param encryptionPath (암호화할 경로 [ex:"C:\\encriptionPath.dat"])
	 * @param key (암호화키 16바이트 문자열)
	 * @throws Exception
	 */
	public static File seedFileEncrypt(InputStream in, long fileLength, String encryptPath, String key) throws Exception {
		SeedFile seed = new SeedFile();
		seed.setKey(key.getBytes());
		return seed.encryptFile(in, fileLength, encryptPath);
	}

	/**
	 * <pre>
	 * Seed128 파일 복호화
	 * (Create File from FileInputStream)
	 * </pre>
	 *
	 * @date 2016. 10. 11.
	 * @author 장인빈 (inbin@jcone.co.kr)
	 * @param in (복호화할 파일스트림)
	 * @param fileLength (복호화할 파일의 크기)
	 * @param decryptPath (복호화된 파일 경로 [ex:"C:\\decriptionPath_decript.txt"])
	 * @param key (암호화키 16바이트 문자열)
	 * @throws Exception
	 */
	public static File seedFileDecrypt(InputStream in, long fileLength, String decryptPath, String key) throws Exception {
		SeedFile seed = new SeedFile();
		seed.setKey(key.getBytes());
		return seed.decryptFile(in, fileLength, decryptPath);
	}

}
