package com.jcone;


public class main {

	public static void main(String[] args) throws Exception {
		try {

			//file to file
			//			File file = new File(args[0]);
			//			Cipher.seedFileEncrypt(file, args[1], args[3]);
			//
			//			File file_enc = new File(args[1]);
			//			Cipher.seedFileDecrypt(file_enc, args[2], args[3]);

			System.out.println(Cipher.encryptString("SEED128", "eeun123@naver.com", "EContractSystemK"));
			System.out.println(Cipher.decryptString("SEED128", "TTBdbNghLRFBV4avqjf59iEeFhlXF1aF75ZIftAAhas=", "EContractSystemK"));

			//			File file = new File("D:/cipher/asd/test00002 (60).pdf");
			//			Cipher.seedFileEncrypt(file, "D:/cipher/asd/test00002 (60)_enc.pdf", "EContractSystemK");
			//
			//			File file_enc = new File("D:/cipher/asd/test00002 (60)_enc.pdf");
			//			Cipher.seedFileDecrypt(file_enc, "D:/cipher/asd/test00002 (60)_dec.pdf", "EContractSystemK");

			//			//file to file
			//			File _1024_file = new File("/software/cipher/test/1024.txt");
			//			File _1024 = Cipher.seedFileEncrypt(_1024_file, "/software/cipher/test/1024_enc", "0123456789abcdef");
			//
			//			File _1024_file_enc = new File("/software/cipher/test/1024_enc");
			//			File _1024_dec = Cipher.seedFileDecrypt(_1024_file_enc, "/software/cipher/test/1024_dec.txt", "0123456789abcdef");
			//
			//			//file to file
			//			File filetofile_file = new File("/software/cipher/test/filetofile.txt");
			//			File filetofile = Cipher.seedFileEncrypt(filetofile_file, "/software/cipher/test/filetofile_enc", "0123456789abcdef");
			//
			//			File filetofile_file_enc = new File("/software/cipher/test/filetofile_enc");
			//			File filetofile_dec = Cipher.seedFileDecrypt(filetofile_file_enc, "/software/cipher/test/filetofile_dec.txt", "0123456789abcdef");
			//
			//			//file to out
			//			File filetoout_file = new File("/software/cipher/test/filetoout.txt");
			//			FileOutputStream filetoout_enc = new FileOutputStream(new File("/software/cipher/test/filetoout_enc"));
			//			FileOutputStream filetoout = Cipher.seedFileEncrypt(filetoout_file, filetoout_enc, "0123456789abcdef");
			//			filetoout_enc.close();
			//			filetoout.close();
			//
			//			File filetoout_encFile = new File("/software/cipher/test/filetoout_enc");
			//			FileOutputStream filetoout_dec = new FileOutputStream(new File("/software/cipher/test/filetoout_dec.txt"));
			//			FileOutputStream filetoout_dec2 = Cipher.seedFileDecrypt(filetoout_encFile, filetoout_dec, "0123456789abcdef");
			//			filetoout_dec.close();
			//			filetoout_dec2.close();
			//
			//			//in to file
			//			File intofile1 = new File("/software/cipher/test/intofile.txt");
			//			FileInputStream intofile_in = new FileInputStream(intofile1);
			//			File intofile = Cipher.seedFileEncrypt(intofile_in, intofile1.length(), "/software/cipher/test/intofile_enc", "0123456789abcdef");
			//			intofile_in.close();
			//
			//			File intofile2 = new File("/software/cipher/test/intofile_enc");
			//			FileInputStream intofile_in2 = new FileInputStream(intofile2);
			//			File intofile_dec = Cipher.seedFileDecrypt(intofile_in2, intofile2.length(), "/software/cipher/test/intofile_dec.txt", "0123456789abcdef");
			//			intofile_in2.close();
			//
			//			//in to out
			//			File intoout1 = new File("/software/cipher/test/intoout.txt");
			//			FileInputStream intoout_in1 = new FileInputStream(intoout1);
			//			FileOutputStream intoout_out1 = new FileOutputStream(new File("/software/cipher/test/intoout_enc"));
			//			FileOutputStream intoout = Cipher.seedFileEncrypt(intoout_in1, intoout1.length(), intoout_out1, "0123456789abcdef");
			//			intoout_in1.close();
			//			intoout_out1.close();
			//
			//			File intoout3 = new File("/software/cipher/test/intoout_enc");
			//			FileInputStream intoout_in2 = new FileInputStream(intoout3);
			//			FileOutputStream intoout_out2 = new FileOutputStream(new File("/software/cipher/test/intoout_dec.txt"));
			//			FileOutputStream intoout_dec = Cipher.seedFileDecrypt(intoout_in2, intoout3.length(), intoout_out2, "0123456789abcdef");
			//			intoout_in2.close();
			//			intoout_out2.close();

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
