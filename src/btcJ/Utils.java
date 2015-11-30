package btcJ;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.lang3.ArrayUtils;


/**
 * General utilities for the second chapter examples.
 */
public class Utils
{
    private static String	digits = "0123456789abcdef";
    
    /**
     * Return length many bytes of the passed in byte array as a hex string.
     * 
     * @param data the bytes to be converted.
     * @param length the number of bytes in the data block to be converted.
     * @return a hex representation of length bytes of data.
     */
    public static String toHex(byte[] data, int length)
    {
        StringBuffer	buf = new StringBuffer();
        
        for (int i = 0; i != length; i++)
        {
            int	v = data[i] & 0xff;
            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }
        
        return buf.toString();
    }
    /**
     * Return the passed in byte array as a hex string.
     * 
     * @param data the bytes to be converted.
     * @return a hex representation of data.
     */
    public static String toHex(byte[] data)
    {
        return toHex(data, data.length);
    }
    
    public static byte[] toHexB(byte[] data) throws DecoderException
    {
     	return toHex(data).getBytes();
    }
    

	public static byte[] varint(int x) throws IOException {
		
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		
		DataOutputStream d = new DataOutputStream(b);

		if (x<0xfd) { //253 unsigned byte
			byte bt = (byte) x;
			d.writeByte(bt);
			byte[] result = b.toByteArray();
			ArrayUtils.reverse(result);
			return result;
		} else if (x<0xffff){ //65 535 unsigned short
			short st = (short) x;
			//d.writeByte(253);
			d.writeShort(st);
			
			byte[] result = b.toByteArray();
			byte[] result2 = new byte[3];
			byte [] bt = new byte[1];
			bt[0] = (byte) 0xfd;
			ArrayUtils.reverse(result);
			System.arraycopy(result, 0, result2, 1, result.length);
			System.arraycopy(bt,0,result2,0,1);
			return result2;	
			
		} else if (x<0xffffffffL) { //4 294 967 295 unsigned int
			d.writeInt(x);
			byte[] result = b.toByteArray();
			byte[] result2 = new byte[5];
			byte [] bt = new byte[1];
			bt[0] = (byte) 0xfe;
			
			ArrayUtils.reverse(result);
			System.arraycopy(result, 0, result2, 1, result.length);
			System.arraycopy(bt,0,result2,0,1);
			return result2;

		} else {
			System.out.println("else");
		}
		
		return null;
	}

	public static byte [] varstr(byte [] ba) throws IOException {
		byte []  bad = new byte [varint(ba.length).length+ ba.length];
		System.arraycopy(varint(ba.length), 0, bad, 0, varint(ba.length).length);
		System.arraycopy(ba,0,bad, varint(ba.length).length, ba.length);
		return bad;
	}

}
