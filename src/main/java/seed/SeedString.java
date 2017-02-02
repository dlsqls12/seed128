package seed;

public class SeedString extends Seed {
	/**
	 * <pre>
	 * Seed128 문자열 암호화
	 * </pre>
	 *
	 * @date 2016. 10. 12.
	 * @author 장인빈 (inbin@jcone.co.kr)
	 * @param plainText
	 * @return
	 */
	public byte[] encrypt(String plainText) {
		byte[] byteIV = { (byte) 0x26, (byte) 0x8D, (byte) 0x66, (byte) 0xA7, (byte) 0x35, (byte) 0xA8, (byte) 0x1A, (byte) 0x81, (byte) 0x6F, (byte) 0xBA, (byte) 0xD9, (byte) 0xFA, (byte) 0x36, (byte) 0x16, (byte) 0x25, (byte) 0x01 };
		int[] seedKey = new int[Seed.NoRoundKeys];
		Seed.SeedRoundKey(seedKey, Seed.key);

		byte[] pbPlain = addPadding(plainText.getBytes(), Seed.SeedBlockSize);
		byte[] pbCipher = new byte[pbPlain.length];

		byte[] sSource = new byte[Seed.SeedBlockSize];
		byte[] sTarget = new byte[Seed.SeedBlockSize];

		int rt = pbPlain.length / Seed.SeedBlockSize;
		for (int j = 0; j < rt; j++) {
			System.arraycopy(pbPlain, (j * Seed.SeedBlockSize), sSource, 0, Seed.SeedBlockSize);

			// CBC 운영모드
			Seed.exclusiveOR(sSource, byteIV);
			Seed.SeedEncrypt(sSource, seedKey, sTarget);
			byteIV = sTarget;

			System.arraycopy(sTarget, 0, pbCipher, (j * Seed.SeedBlockSize), sTarget.length);

		}

		return pbCipher;
	}

	/**
	 * <pre>
	 * Seed128 문자열 복호화
	 * </pre>
	 *
	 * @date 2016. 10. 12.
	 * @author 장인빈 (inbin@jcone.co.kr)
	 * @param encryptBytes
	 * @return
	 */
	public String decrypt(byte[] encryptBytes) {
		byte[] byteIV = { (byte) 0x26, (byte) 0x8D, (byte) 0x66, (byte) 0xA7, (byte) 0x35, (byte) 0xA8, (byte) 0x1A, (byte) 0x81, (byte) 0x6F, (byte) 0xBA, (byte) 0xD9, (byte) 0xFA, (byte) 0x36, (byte) 0x16, (byte) 0x25, (byte) 0x01 };
		int[] seedKey = new int[Seed.NoRoundKeys];
		Seed.SeedRoundKey(seedKey, Seed.key);

		byte decryptBytes[] = new byte[encryptBytes.length];

		byte sSource[] = new byte[Seed.SeedBlockSize];
		byte sTarget[] = new byte[Seed.SeedBlockSize];

		int rt = encryptBytes.length / Seed.SeedBlockSize;
		for (int j = 0; j < rt; j++) {
			System.arraycopy(encryptBytes, (j * Seed.SeedBlockSize), sSource, 0, Seed.SeedBlockSize);

			Seed.SeedDecrypt(sSource, seedKey, sTarget);
			// CBC 운영모드
			Seed.exclusiveOR(sTarget, byteIV);
			System.arraycopy(sSource, 0, byteIV, 0, Seed.SeedBlockSize);

			System.arraycopy(sTarget, 0, decryptBytes, (j * Seed.SeedBlockSize), Seed.SeedBlockSize);

		}

		decryptBytes = removePadding(decryptBytes, Seed.SeedBlockSize);
		return new String(decryptBytes);
	}

	/**
	 * 패킷내 정의된 필드의 길이가 남을때 패딩개수로 채운다
	 * PKCSPadding
	 *
	 * @param b : 대상 바이트 배열
	 * @param blockSize : 블럭 길이
	 */
	private byte[] addPadding(byte[] source, int blockSize) {
		int paddingCnt = source.length % blockSize;
		byte[] paddingResult = null;

		if (paddingCnt != 0) {
			paddingResult = new byte[source.length + (blockSize - paddingCnt)];

			System.arraycopy(source, 0, paddingResult, 0, source.length);

			// 패딩해야 할 갯수 - 1 (마지막을 제외)까지 0x00 값을 추가한다.
			int addPaddingCnt = blockSize - paddingCnt;
			for (int i = 0; i < addPaddingCnt; i++) {
				paddingResult[source.length + i] = (byte) addPaddingCnt;
			}
		} else {
			paddingResult = source;
		}
		return paddingResult;
	}

	/**
	 * 패킷내 패딩된 패딩개수를 제거한다.
	 * PKCSPadding
	 *
	 * @param source
	 * @param blockSize
	 * @return
	 */
	private byte[] removePadding(byte[] source, int blockSize) {
		byte[] paddingResult = null;
		boolean isPadding = false;

		// 패딩 된 count를 찾는다.
		int lastValue = source[source.length - 1];

		if (0 < lastValue) {
			for (int i = 1; i <= lastValue; i++) {
				if (source[source.length - i] != lastValue) {
					isPadding = false;
					break;
				}
				isPadding = true;
			}

		} else {
			isPadding = false;
		}

		if (isPadding) {
			paddingResult = new byte[source.length - lastValue];
			System.arraycopy(source, 0, paddingResult, 0, paddingResult.length);
		} else {
			paddingResult = source;
		}

		return paddingResult;
	}

}
