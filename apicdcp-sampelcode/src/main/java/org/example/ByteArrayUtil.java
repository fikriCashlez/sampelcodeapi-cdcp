package org.example;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

public class ByteArrayUtil {
	public static byte[] padLeftWithZeroes(byte[] byteArray, int length) {
		byte[] newByteArray = new byte[length];
		int offset = length - byteArray.length;
		for(int i = 0; i < offset; i++) {
			newByteArray[i] = (byte)0x00;
		}
		
		for(int i = 0, j = offset; i < byteArray.length; i ++) {
			newByteArray[j++] = byteArray[i];
		}
		
		return newByteArray;
	}
	
	public static byte[] padLeftWith0xFF(byte[] byteArray, int length) {
		byte[] newByteArray = new byte[length];
		int offset = length - byteArray.length;
		for(int i = 0; i < offset; i++) {
			newByteArray[i] = (byte)0xFF;
		}
		
		for(int i = 0, j = offset; i < byteArray.length; i ++) {
			newByteArray[j++] = byteArray[i];
		}
		
		return newByteArray;
	}
	
	public static byte[] and(byte[] array1, byte[] array2) {
		byte[] maskedArray = new byte[array1.length];
		for(int i = 0; i < array1.length; i++) {
			int a = array1[i] & 0xFF;
			int b = array2[i] & 0xFF;
			int result = a & b;
			maskedArray[i] = (byte)result;
		}
		
		return maskedArray;
	}
	
	public static byte[] or(byte[] array1, byte[] array2) {
		byte[] maskedArray = new byte[array1.length];
		for(int i = 0; i < array1.length; i++) {
			int a = array1[i] & 0xFF;
			int b = array2[i] & 0xFF;
			int result = a | b;
			maskedArray[i] = (byte)result;
		}
		
		return maskedArray;
	}
	
	public static byte[] xor(byte[] array1, byte[] array2) {
		byte[] maskedArray = new byte[array1.length];
		for(int i = 0; i < array1.length; i++) {
			int a = array1[i] & 0xFF;
			int b = array2[i] & 0xFF;
			int result = a ^ b;
			maskedArray[i] = (byte)result;
		}
		
		return maskedArray;
	}
	
	public static byte[] subArray(byte[] array, int from, int to) {
		int length = (to - from) + 1;
		byte[] subArray = new byte[length];
		
		for(int i = 0, j = from; j < to + 1; i++, j++) {
			subArray[i] = array[j];
		}
		
		return subArray;
	}
	
	public static byte[] join(byte[] left, byte[] right) {
		byte[] result = new byte[left.length + right.length];

		System.arraycopy(left, 0, result, 0, left.length);

		System.arraycopy(right, 0, result, left.length, right.length);
		
		return result;
	}

	public static byte[] shiftRight(byte[] byteArray, int n) {
		byte[] newArray = new byte[byteArray.length];
		
		BigInteger intFromOfArray = new BigInteger(byteArray);
		intFromOfArray = intFromOfArray.shiftRight(n);
		
		byte[] intToArray = intFromOfArray.toByteArray();
		if(intToArray.length < newArray.length) {
			int offset = newArray.length - intToArray.length;
			for(int i = 0; i < offset; i ++) {
				newArray[i] = 0x00;
			}
			
			for(int i = offset, j = 0; i < newArray.length; i++, j++) {
				newArray[i] = intToArray[j];
			}
		}
		
		return newArray;
	}

	/**
	 * Multiple data merge
	 *
	 * @param data Data Array
	 * @return An array of merged data
	 */
	public static byte[] merge(byte[]... data) {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		try {
			for (byte[] d : data) {
				if (d == null) {
					throw new IllegalArgumentException("");
				}
				buffer.write(d);
			}
			return buffer.toByteArray();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				buffer.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		return null;
	}
	/**
	 * Get a sub array
	 *
	 * @param data   data
	 * @param offset offset （0-data.length）
	 * @param len    length
	 * @return sub array
	 */
	public static byte[] subBytes(byte[] data, int offset, int len) {
		if ((data == null) || (data.length == 0)) {
			return null;
		}

		if (offset < 0 || data.length <= offset) {
			return null;
		}

		if (len < 0 || data.length < offset + len) {
			len = data.length - offset;
		}

		byte[] ret = new byte[len];

		System.arraycopy(data, offset, ret, 0, len);
		return ret;
	}

	/**
	 * Converts an integer to a 4-byte array in small-endian mode
	 *
	 * @param intValue integer
	 * @return byte array
	 */
	public static byte[] intToBytesByLow(int intValue) {
		byte[] bytes = new byte[4];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) ((intValue >> ((3 - i) << 3)) & 0xFF);
		}
		return bytes;
	}
}
