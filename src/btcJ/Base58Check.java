package btcJ;

import java.security.MessageDigest;

public class Base58Check {


	public static byte[] decode(String string) {
		// TODO Auto-generated method stub
/*	    leadingOnes = countLeadingChars(s, '1')
	    	    print(s[0])
	    	    
	    	    #Testnet
	    	    if s[0] in ['K', 'c']:
	    	        #print('compressed')
	    	        compressed = True
	    	    #Mainnet    
	    	    else:
	    	        compressed = False
	    	        
	    	            
	    	    s = base256encode(base58decode(s))
	    	    #print('s',s)
	    	    result = b'\0' * leadingOnes + s[:-4]
	    	    chk = s[-4:] 
	    	    #print('chk',chk)
	    	    checksum = hashlib.sha256(hashlib.sha256( result ).digest()).digest()[0:4]
	    	    #print('checksum',checksum)
	    	    assert(chk == checksum)
	    	    version = result[0]
	    	    if compressed:
	    	        return result[1:-1]
	    	    else:
	    	        return result[1:]
*/		
		byte [] s = null;
		byte [] chk = new byte[4];
		
		boolean compressed = false;
		int leadingOnes = 0;
		for (int i = 0; i < string.length(); i++) {
			if (string.charAt(i)== '1') {
				leadingOnes += 1;
			} else {
				break;
			}
			
		}
		if (string.charAt(0)=='K' || string.charAt(0)== 'c') {
			compressed = true;
		}
		
		s = Base58.decode(string);
		//System.out.println("Base58Check:" + Utils.toHex(s));
		
		byte[] s2 = new byte[s.length  - 4 ];
		int bl = compressed ? s2.length -1 : s2.length;
		byte[] s3 = new byte[bl-1];
		byte[] hash2 = null;
		
		System.arraycopy(s, 0	, s2, 0 , s.length - 4  );
		//System.out.println("Base58Check2:" + Utils.toHex(s2));

		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(s2);
			hash2 = digest.digest(hash);


		} catch (Exception e) {
			// TODO: handle exception
		}
		byte[] checksum = new byte[4];
		System.arraycopy(hash2, 0, checksum, 0, checksum.length );
		System.arraycopy(s2, 1, s3, 0, bl-1);
		
		//System.out.println("s3  " + Utils.toHex(s3));
		return s3;
	}

	public static String encode(byte version , byte[] ba, boolean compressed) {
		// TODO Auto-generated method stub
/*	    if (compressed=='yes'):
	        s = bytes((version,)) + payload 
	    else:
	        s = bytes((version,)) + payload
	    
	    checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]
	    result = s + checksum 
	        
	    leadingZeros = countLeadingChars(result, 0)
	    return '1' * leadingZeros + base58encode(base256decode(result)) 
*/
		int leadingZeros = 0;
		for (int i = 0; i < ba.length; i++) {
			if ((char) ba[i] == '1') {
				leadingZeros += 1;
			} else {
				break;
			}
			
		}
		byte[] bav = new byte[1];
		bav[0] = (byte)version;
		byte [] ba2 = new  byte[ba.length+1];
		byte[] hash2 = null;
		
		System.arraycopy(bav	, 0, ba2, 0, 1);
		System.arraycopy(ba, 0, ba2, 1, ba.length);
		//System.out.println("ba2    " + Utils.toHex(ba2));
		
		
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(ba2);
			hash2 = digest.digest(hash);


		} catch (Exception e) {
			// TODO: handle exception
		}
		byte[] checksum = new byte[4];
		byte[] ba4 = new byte[ba2.length + checksum.length];
		System.arraycopy(hash2, 0, checksum, 0, checksum.length );
		
		
		System.arraycopy(ba2, 0, ba4, 0, ba2.length);
		System.arraycopy(checksum, 0, ba4, ba2.length, checksum.length);
		//System.out.println(Base58.encode(ba4));
		return Base58.encode(ba4);
	}

}
