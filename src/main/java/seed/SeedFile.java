package seed;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

public class SeedFile extends Seed {
	private int BYTE_SIZE = 1024;
	private byte[] buffer = new byte[BYTE_SIZE];

	/**
	 * <pre>
	 * Seed128 암호화
	 * </pre>
	 *
	 * @date 2016. 10. 12.
	 * @author 장인빈 (inbin@jcone.co.kr)
	 * @param sbuffer
	 * @param szKey
	 * @return
	 */
	private byte[] encrypt(byte[] sbuffer, byte szKey[]) {
		byte[] byteIV = { (byte) 0x26, (byte) 0x8D, (byte) 0x66, (byte) 0xA7, (byte) 0x35, (byte) 0xA8, (byte) 0x1A, (byte) 0x81, (byte) 0x6F, (byte) 0xBA, (byte) 0xD9, (byte) 0xFA, (byte) 0x36, (byte) 0x16, (byte) 0x25, (byte) 0x01 };

		int sRoundKey[] = new int[Seed.NoRoundKeys];
		Seed.SeedRoundKey(sRoundKey, szKey);

		byte[] inDataBuffer = sbuffer;
		byte[] encryptBytes = new byte[inDataBuffer.length];

		byte sSource[] = new byte[Seed.SeedBlockSize];
		byte sTarget[] = new byte[Seed.SeedBlockSize];

		int rt = inDataBuffer.length / Seed.SeedBlockSize;
		for (int j = 0; j < rt; j++) {
			System.arraycopy(inDataBuffer, (j * Seed.SeedBlockSize), sSource, 0, Seed.SeedBlockSize);

			// CBC 운영모드
			Seed.exclusiveOR(sSource, byteIV);
			Seed.SeedEncrypt(sSource, sRoundKey, sTarget);
			byteIV = sTarget;

			System.arraycopy(sTarget, 0, encryptBytes, (j * Seed.SeedBlockSize), sTarget.length);
		}

		return encryptBytes;
	}

	/**
	 * <pre>
	 * Seed128 복호화
	 * </pre>
	 *
	 * @date 2016. 10. 12.
	 * @author 장인빈 (inbin@jcone.co.kr)
	 * @param encryptBytes
	 * @param szKey
	 * @return
	 */
	private byte[] decrypt(byte[] encryptBytes, byte[] szKey) {
		byte[] byteIV = { (byte) 0x26, (byte) 0x8D, (byte) 0x66, (byte) 0xA7, (byte) 0x35, (byte) 0xA8, (byte) 0x1A, (byte) 0x81, (byte) 0x6F, (byte) 0xBA, (byte) 0xD9, (byte) 0xFA, (byte) 0x36, (byte) 0x16, (byte) 0x25, (byte) 0x01 };

		int sRoundKey[] = new int[Seed.NoRoundKeys];
		Seed.SeedRoundKey(sRoundKey, szKey);

		byte[] decryptBytes = new byte[encryptBytes.length];

		byte sSource[] = new byte[Seed.SeedBlockSize];
		byte sTarget[] = new byte[Seed.SeedBlockSize];

		int rt = encryptBytes.length / Seed.SeedBlockSize;
		for (int j = 0; j < rt; j++) {
			System.arraycopy(encryptBytes, (j * Seed.SeedBlockSize), sSource, 0, Seed.SeedBlockSize);

			Seed.SeedDecrypt(sSource, sRoundKey, sTarget);
			// CBC 운영모드
			Seed.exclusiveOR(sTarget, byteIV);
			System.arraycopy(sSource, 0, byteIV, 0, Seed.SeedBlockSize);

			System.arraycopy(sTarget, 0, decryptBytes, (j * Seed.SeedBlockSize), Seed.SeedBlockSize);
		}

		return decryptBytes;
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
	 * @param encryptionPath (암호화할 경로 [ex:"C:\\encriptionPath.dat"])
	 * @throws Exception
	 */
	public File encryptFile(File file, String encryptionPath) throws Exception {
		InputStream in = new FileInputStream(file);

		File wFile = new File(encryptionPath);
		if (wFile.exists()) {
			throw new Exception("File already exist.");
		} else {
			wFile.createNewFile();
		}
		OutputStream out = new FileOutputStream(wFile);
		if (file.length() > 0) {
			while (in.read(buffer) != -1) {
				byte[] outBytes = encrypt(buffer, Seed.key);
				out.write(outBytes);
			}
			int paddingCnt = (file.length() % BYTE_SIZE) == 0 ? 0 : (BYTE_SIZE - (int) (file.length() % BYTE_SIZE));
			int setByteCnt = paddingCnt / 255;
			for (int i = 0; i < setByteCnt; i++) {
				out.write(255);
			}
			out.write(paddingCnt % 255);
		}
		if (out != null) {
			out.close();
		}
		if (in != null) {
			in.close();
		}

		return new File(encryptionPath);
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
	 * @param decryptionPath (복호화할 경로 [ex:"C:\\decriptionPath.txt"])
	 * @throws Exception
	 */
	public File decryptFile(File file, String decryptionPath) throws Exception {
		InputStream in = new FileInputStream(file);

		File wFile = new File(decryptionPath);
		if (wFile.exists()) {
			throw new Exception("File already exist.");
		} else {
			wFile.createNewFile();
		}
		OutputStream out = new FileOutputStream(wFile);
		if (file.length() > 0) {
			int cnt = (int) (file.length() / buffer.length);
			int eof = 0;
			byte[] outBytes = null;
			for (int i = 0; i < cnt; i++) {
				eof = in.read(buffer);
				outBytes = decrypt(buffer, Seed.key);
				if (i != cnt - 1) {
					out.write(outBytes);
				}
			}
			int paddingCnt = 0;
			while ((eof = in.read()) != -1) {
				paddingCnt += eof;
			}
			byte[] lastBytes = new byte[buffer.length - paddingCnt];
			lastBytes = Arrays.copyOfRange(outBytes, 0, buffer.length - paddingCnt);
			out.write(lastBytes);
		}
		if (out != null) {
			out.close();
		}
		if (in != null) {
			in.close();
		}

		return new File(decryptionPath);
	}

	/**
	 * <pre>
	 * Seed128 파일 암호화
	 * (Write in FileOutputStream from File)
	 * </pre>
	 *
	 * @date 2016. 10. 11.
	 * @author 장인빈 (inbin@jcone.co.kr)
	 * @param file (암호화할 파일 객체)
	 * @param out (암호화될 파일스트림)
	 * @throws Exception
	 */
	public OutputStream encryptFile(File file, OutputStream out) throws Exception {
		InputStream in = new FileInputStream(file);

		if (file.length() > 0) {
			while (in.read(buffer) != -1) {
				byte[] outBytes = encrypt(buffer, Seed.key);
				out.write(outBytes);
			}
			int paddingCnt = (file.length() % BYTE_SIZE) == 0 ? 0 : (BYTE_SIZE - (int) (file.length() % BYTE_SIZE));
			int setByteCnt = paddingCnt / 255;
			for (int i = 0; i < setByteCnt; i++) {
				out.write(255);
			}
			out.write(paddingCnt % 255);
		}
		if (in != null) {
			in.close();
		}

		return out;
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
	 * @throws Exception
	 */
	public OutputStream decryptFile(File file, OutputStream out) throws Exception {
		InputStream in = new FileInputStream(file);

		if (file.length() > 0) {
			int cnt = (int) (file.length() / buffer.length);
			int eof = 0;
			byte[] outBytes = null;
			for (int i = 0; i < cnt; i++) {
				eof = in.read(buffer);
				outBytes = decrypt(buffer, Seed.key);
				if (i != cnt - 1) {
					out.write(outBytes);
				}
			}
			int paddingCnt = 0;
			while ((eof = in.read()) != -1) {
				paddingCnt += eof;
			}
			byte[] lastBytes = new byte[buffer.length - paddingCnt];
			lastBytes = Arrays.copyOfRange(outBytes, 0, buffer.length - paddingCnt);

			out.write(lastBytes);
		}
		if (in != null) {
			in.close();
		}
		return out;
	}

	/**
	 * <pre>
	 * Seed128 파일 암호화
	 * (Write in FileOutputStream from FileInputStream)
	 * </pre>
	 *
	 * @date 2016. 10. 12.
	 * @author 장인빈 (inbin@jcone.co.kr)
	 * @param in (암호화할 파일스트림)
	 * @param fileLength (암호화할 파일의 크기)
	 * @param out (암호화될 파일스트림)
	 * @return
	 * @throws Exception
	 */
	public OutputStream encryptFile(InputStream in, long fileLength, OutputStream out) throws Exception {
		if (fileLength > 0) {
			while (in.read(buffer) != -1) {
				byte[] outBytes = encrypt(buffer, Seed.key);
				out.write(outBytes);
			}
			int paddingCnt = (fileLength % BYTE_SIZE) == 0 ? 0 : (BYTE_SIZE - (int) (fileLength % BYTE_SIZE));
			int setByteCnt = paddingCnt / 255;
			for (int i = 0; i < setByteCnt; i++) {
				out.write(255);
			}
			out.write(paddingCnt % 255);
		}
		return out;
	}

	/**
	 * <pre>
	 * Seed128 파일 복호화
	 * (Write in FileOutputStream from FileInputStream)
	 * </pre>
	 *
	 * @date 2016. 10. 12.
	 * @author 장인빈 (inbin@jcone.co.kr)
	 * @param in (복호화할 파일스트림)
	 * @param fileLength (복호화할 파일의 크기)
	 * @param out (복호화될 파일스트림)
	 * @return
	 * @throws Exception
	 */
	public OutputStream decryptFile(InputStream in, long fileLength, OutputStream out) throws Exception {
		if (fileLength > 0) {
			int cnt = (int) (fileLength / buffer.length);
			int eof = 0;
			byte[] outBytes = null;
			for (int i = 0; i < cnt; i++) {
				eof = in.read(buffer);
				outBytes = decrypt(buffer, Seed.key);
				if (i != cnt - 1) {
					out.write(outBytes);
				}
			}
			int paddingCnt = 0;
			while ((eof = in.read()) != -1) {
				paddingCnt += eof;
			}
			byte[] lastBytes = new byte[buffer.length - paddingCnt];
			lastBytes = Arrays.copyOfRange(outBytes, 0, buffer.length - paddingCnt);

			out.write(lastBytes);
		}
		return out;
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
	 * @throws Exception
	 */
	public File encryptFile(InputStream in, long fileLength, String encryptionPath) throws Exception {
		File wFile = new File(encryptionPath);
		if (wFile.exists()) {
			throw new Exception("File already exist.");
		} else {
			wFile.createNewFile();
		}
		FileOutputStream out = new FileOutputStream(wFile);

		if (fileLength > 0) {
			while (in.read(buffer) != -1) {
				byte[] outBytes = encrypt(buffer, Seed.key);
				out.write(outBytes);
			}
			int paddingCnt = (fileLength % BYTE_SIZE) == 0 ? 0 : (BYTE_SIZE - (int) (fileLength % BYTE_SIZE));
			int setByteCnt = paddingCnt / 255;
			for (int i = 0; i < setByteCnt; i++) {
				out.write(255);
			}
			out.write(paddingCnt % 255);

			if (out != null) {
				out.close();
			}
		}

		return new File(encryptionPath);
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
	 * @param decryptionPath (복호화할 경로 [ex:"C:\\decriptionPath.txt"])
	 * @throws Exception
	 */
	public File decryptFile(InputStream in, long fileLength, String decryptionPath) throws Exception {
		File wFile = new File(decryptionPath);
		if (wFile.exists()) {
			throw new Exception("File already exist.");
		} else {
			wFile.createNewFile();
		}
		FileOutputStream out = new FileOutputStream(wFile);
		if (fileLength > 0) {
			int cnt = (int) (fileLength / buffer.length);
			int eof = 0;
			byte[] outBytes = null;
			for (int i = 0; i < cnt; i++) {
				eof = in.read(buffer);
				outBytes = decrypt(buffer, Seed.key);
				if (i != cnt - 1) {
					out.write(outBytes);
				}
			}
			int paddingCnt = 0;
			while ((eof = in.read()) != -1) {
				paddingCnt += eof;
			}
			byte[] lastBytes = new byte[buffer.length - paddingCnt];
			lastBytes = Arrays.copyOfRange(outBytes, 0, buffer.length - paddingCnt);

			out.write(lastBytes);
		}
		if (out != null) {
			out.close();
		}

		return new File(decryptionPath);
	}

}
