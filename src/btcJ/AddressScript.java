package btcJ;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import org.apache.commons.codec.DecoderException;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.math.ec.ECPoint;


public class AddressScript {
	
	public static PrivateKey loadPrivateKey(String key64) throws GeneralSecurityException {
	    byte[] clear = Base64.getDecoder().decode(key64);
	    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(clear);
	    KeyFactory fact = KeyFactory.getInstance("ECDSA");
	    PrivateKey priv = fact.generatePrivate(keySpec);
	    Arrays.fill(clear, (byte) 0);
	    return priv;
	}


	public static PublicKey loadPublicKey(String stored) throws GeneralSecurityException {
	    byte[] data = Base64.getDecoder().decode(stored);
	    X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
	    KeyFactory fact = KeyFactory.getInstance("DSA");
	    return fact.generatePublic(spec);
	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		//String wif = new String("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ");
		//boolean compressed = false;
		//boolean testnet = false;
		
		
		//http://chimera.labs.oreilly.com/books/1234000001802/ch04.html#_implementing_keys_and_addresses_in_python
		//Antonopolous
		
		//String wif = "KyBsPXxTuVD82av65KZkrGrWi5qLMah5SdNq6uftawDbgKa2wv6S";
		//boolean compressed = true;
		//boolean testnet = false;

		
		
		String wif = "5JG9hT3beGTJuUAmCQEmNaxAuMacCTfXuw1R3FCXig23RQHMr4K";
		wif = "5Kb6aGpijtrb8X28GzmWtbcGZCG8jHQWFJcWugqo3MwKRvC8zyu";
		boolean compressed = false;
		boolean testnet = false;
		
		byte[] wif_enc  = new byte[ wif.length() ];

		System.out.println("    ****************************************");
		System.out.println("    ***** WIF to Private key ***************");
		System.out.println("    ****************************************");

		System.out.println("1 - Take a Wallet Import Format string");
		System.out.println("    " + wif);

		wif_enc = Base58.decode(wif);
		
		byte[] wif_enc_sh = new byte[ wif_enc.length-4];
		byte[] wif_enc_fin = new byte[ wif_enc.length-5];
		System.out.println("2 - Convert it to a byte string using Base58Check encoding");

		System.out.println("    " + Utils.toHex(wif_enc).toUpperCase());

		System.out.println("3 - Drop the last 4 checksum bytes from the byte string");
		System.arraycopy(wif_enc, 0, wif_enc_sh, 0, wif_enc.length - 4);
		System.out.println("    " + Utils.toHex(wif_enc_sh).toUpperCase());


		System.out.println("4 - Dropping first byte. This is the private key");
		System.arraycopy(wif_enc_sh, 1, wif_enc_fin, 0, wif_enc.length - 5);
		System.out.println("    " + Utils.toHex(wif_enc_fin).toUpperCase());
		
		String private_key = new String(Utils.toHex(wif_enc_fin).toUpperCase());
		
		System.out.println();
		System.out.println("    ****************************************");
		System.out.println("    ***** WIF Checksum       ***************");
		System.out.println("    ****************************************");
		System.out.println("1 - Take a Wallet Import Format string");
		System.out.println("    " + wif);

		wif_enc = Base58.decode(wif);
		System.out.println("2 - Convert it to a byte string using Base58Check encoding");

		System.out.println("    " + Utils.toHex(wif_enc).toUpperCase());

		System.out.println("3 - Drop the last 4 checksum bytes from the byte string");
		System.arraycopy(wif_enc, 0, wif_enc_sh, 0, wif_enc.length - 4);
		System.out.println("    " + Utils.toHex(wif_enc_sh).toUpperCase());

		byte[] hash = new byte[256];
		byte[] hash2 = new byte[256];
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			hash = digest.digest(wif_enc_sh);
			hash2 = digest.digest(hash);


		} catch (Exception e) {
			// TODO: handle exception
		}
		System.out.println("4 - Perform SHA-256 hash on the shortened string");
		System.out.println("    " + Utils.toHex(hash).toUpperCase());
		System.out.println("5 - Perform SHA-256 hash on result of SHA-256 hash");
		System.out.println("    " + Utils.toHex(hash2).toUpperCase());
		byte[] checksum = new byte[4];
		System.out.println("6 - Take the first 4 bytes of the second SHA-256 hash, this is the checksum");
		System.arraycopy(hash2, 0, checksum, 0, checksum.length );
		System.out.println("    " + Utils.toHex(checksum).toUpperCase());
		System.out.println("7 - Make sure it is the same, as the last 4 bytes from point 2");
		System.arraycopy(wif_enc, wif_enc.length - 4, checksum, 0, checksum.length );
		System.out.println("    " + Utils.toHex(checksum).toUpperCase());
		System.out.println("8 - If they are, and the byte string from point 2 starts with 0x80 (0xef for testnet addresses), then there is no error.");
		System.out.println();
		System.out.println("    ****************************************");
		System.out.println("    ***** Private Key to WIF ***************");
		System.out.println("    ****************************************");
		System.out.println("1 - Take a private key");
		private_key = "80" + private_key  ;
		System.out.println("    " + private_key );
		
		byte[] bytes3 = new byte[private_key.length()];
		try {
			bytes3 = org.apache.commons.codec.binary.Hex.decodeHex(private_key.toCharArray());
		} catch (DecoderException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			hash = digest.digest(bytes3);
			hash2 = digest.digest(hash);


		} catch (Exception e) {
			// TODO: handle exception
		}
		
		
		
		
		
		System.out.println("3 - Perform SHA-256 hash on the extended key");
		System.out.println("    " + Utils.toHex(hash).toUpperCase());
		System.out.println("4 - Perform SHA-256 hash on result of SHA-256 hash");
		System.out.println("    " + Utils.toHex(hash2).toUpperCase());
		checksum = new byte[4];
		System.out.println("5 - Take the first 4 bytes of the second SHA-256 hash, this is the checksum");
		System.arraycopy(hash2, 0, checksum, 0, checksum.length );
		System.out.println("    " + Utils.toHex(checksum).toUpperCase());
		System.out.println("6 - Add the 4 checksum bytes from point 5 at the end of the extended key from point 2");
		System.out.println("    "+private_key + Utils.toHex(checksum));
		System.out.println("7 - Convert the result from a byte string into a base58 string using Base58Check encoding. This is the Wallet Import Format");

		byte[] combined = new byte[bytes3.length + checksum.length];

		for (int i = 0; i < combined.length; ++i)
		{
		    combined[i] = i < bytes3.length ? bytes3[i] : checksum[i - bytes3.length];
		}
		System.out.println(	"    wif:"+	Base58.encode(combined).toUpperCase());
		
		
		System.out.println();
		System.out.println("    ****************************************");
		System.out.println("    ***** Private Key to Bitcoin Address ***");
		System.out.println("    ****************************************");
		
		System.out.println("1 - Take a private key");
		private_key = "EF" + private_key  ;
		//System.out.println("    " + private_key );
		
		//byte[] b58 = Base58.decode("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ");
		//System.out.println(b58[0]);
		//System.arraycopy(Base58.decode("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"), 1, pk, 0, 32);
	    
//	    ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
	    X9ECParameters ecp = SECNamedCurves.getByName("secp256k1");
	    ECDomainParameters domainParams = new ECDomainParameters(ecp.getCurve(),
	                                                             ecp.getG(), ecp.getN(), ecp.getH(),
	                                                             ecp.getSeed());
	    ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters(new BigInteger(1,wif_enc_fin), domainParams) ;
	    byte[] publicKeyBIBytes = privateKey.getD().toByteArray();
	    //System.out.println(privateKeyBytes.length);
	    // First print our generated private key and public key
		System.out.println("1 - Public ECDSA Key");
	    System.out.println("     " + Utils.toHex(publicKeyBIBytes));

	    // Then calculate the public key only using domainParams.getG() and private key
	    ECPoint Q = domainParams.getG().multiply(new BigInteger(publicKeyBIBytes));
	    System.out.println("Calculated public key: " + Utils.toHex(Q.getEncoded(compressed)));
	    
	    

		
		
		byte[] publicKeyBytes = Q.getEncoded(compressed);
		byte[] out = new byte[20];
		
		
		//RIPEMD160Digest digest160 = new RIPEMD160Digest();
		//digest.update(strBytes, 0, strBytes.length);
		//try {
			//bytes3 = org.apache.commons.codec.binary.Hex.decodeHex(private_key.toCharArray());
		//} catch (DecoderException e1) {
			// TODO Auto-generated catch block
			//e1.printStackTrace();
		//}
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			hash = digest.digest(publicKeyBytes);
			hash2 = digest.digest(hash);
			RIPEMD160Digest digest160 = new RIPEMD160Digest();
			digest160.update(hash, 0, hash.length);
			digest160.doFinal(out, 0);
			
		} catch (Exception e) {
			// TODO: handle exception
		}
		
		
		
		
		
		System.out.println("2 - SHA-256 hash of 1");
		System.out.println("    " + Utils.toHex(hash).toUpperCase());
		System.out.println("3 - RIPEMD-160 Hash of 2");
		System.out.println("    " + Utils.toHex(out).toUpperCase());
		System.out.println("4 - Adding network bytes to 3");
		System.out.println("    " + "00" + Utils.toHex(out).toUpperCase());
		
		try {
			bytes3 = org.apache.commons.codec.binary.Hex.decodeHex(("00" + Utils.toHex(out).toUpperCase()).toCharArray());
		} catch (DecoderException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			hash = digest.digest(bytes3);
			hash2 = digest.digest(hash);
			
		} catch (Exception e) {
			// TODO: handle exception
		}
		
		System.out.println("5 - SHA-256 hash of 4");
		System.out.println("    " + Utils.toHex(hash).toUpperCase());
		System.out.println("6 - SHA-256 hash of 5");
		System.out.println("    " + Utils.toHex(hash2).toUpperCase());
		System.out.println("7 - First four bytes of 6");
		System.arraycopy(hash2, 0, checksum, 0, checksum.length );
		System.out.println("    " +  Utils.toHex(checksum));
		
		System.out.println("8 - Adding 7 at the end of 4");
		System.out.println("    " + "00" + Utils.toHex(out).toUpperCase() + Utils.toHex(checksum));
		System.out.println("9 - Base58 encoding of 8");
		
		combined = new byte[1 + out.length + checksum.length];

		for (int i = 0; i < combined.length; ++i)
		{
		    combined[i] = i < bytes3.length ? bytes3[i] : checksum[i - bytes3.length];
		}
		System.out.println(	"    Address:"+	Base58.encode(combined));
		
		
		
		
		
		
		
		
		System.out.println("EF".toCharArray()[0] + " " + "EF".toCharArray()[1]);
		System.out.println("EF".getBytes()[0] + " " +  "EF".getBytes()[1]);
		try {
			byte[] temp = org.apache.commons.codec.binary.Hex.decodeHex( "EF".toCharArray() );
			System.out.println(temp[0]);
		} catch (DecoderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		
		/*
        //Signature           signature = Signature.getInstance("ECDSA", "BC");

        // generate a signature
        private_key = "4f89c38435a03373a5fc797a2eeb5e93ffa958639ee063f8968c3545a39a910a";
        
        
        //ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECCurve curve = params.getCurve();
        
        ECPrivateKeySpec priKeySpec = new ECPrivateKeySpec(
                new BigInteger("145642755521911534651321230007534120304391871461646461466464667494947990"), // d
                params);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(      		
        		params.getCurve().decodePoint(Hex.decode("041906010CDC4CFAFC11A4588FE26197C979BD31F76E19D9F4B91B5660838AC9ACE66A93E5F8AED4354E54DFED61D4B0DA0E6EBF8B314ED0BF99E663FB0AF3C5A3")), 
                params );
		try {
	        KeyFactory fact = null;
				fact = KeyFactory.getInstance("ECDSA", "BC");
				try {
					PublicKey           vKey = fact.generatePublic(pubKeySpec);
					System.out.println(vKey.toString());
					PrivateKey          sKey = fact.generatePrivate(priKeySpec);
					System.out.println(sKey.toString());
					
				} catch (InvalidKeySpecException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			} catch (NoSuchAlgorithmException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (NoSuchProviderException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
        
        
        		print('2 - Add a 0x80 byte in front of it for mainnet addresses or 0xef for testnet addresses.')
		payload = codecs.decode(private_key.encode("utf-8"),'hex')
		if (net == 'main'):
		    versionb = b'\x80'
		else:
		    versionb = b'\xef'
		s = versionb + payload
		print('   ', codecs.encode(s, "hex").decode().upper())
		print ('3 - Perform SHA-256 hash on the extended key')
		first_hash = hashlib.sha256(s).hexdigest()
		print ('   ',first_hash)
		print('   ',first_hash == '8147786C4D15106333BF278D71DADAF1079EF2D2440A4DDE37D747DED5403592'.lower())
		print( '4 - Perform SHA-256 hash on result of SHA-256 hash')
		second_hash = hashlib.sha256(codecs.decode(first_hash.encode("utf-8"), "hex")).hexdigest()
		print ('   ',second_hash.upper())
		print('   ',second_hash == '507A5B8DFED0FC6FE8801743720CEDEC06AA5C6FCA72B07C49964492FB98A714'.lower())
		print( '5 - Take the first 4 bytes of the second SHA-256 hash, this is the checksum')
		checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]
		print ('   ',hashlib.sha256(hashlib.sha256(s).digest()).hexdigest()[0:8])
		print('6 - Add the 4 checksum bytes from point 5 at the end of the extended key from point 2')
		result = s + checksum
		print ('   ',codecs.encode(result,'hex').decode().upper())
		print ('   ',codecs.encode(result,'hex').decode()=='800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D507A5B8D'.lower())
		leadingZeros = utils.countLeadingChars(result, '\0')

		print('7 - Convert the result from a byte string into a base58 string using Base58Check encoding. This is the Wallet Import Format')
		#print(utils.base256decode( result ))
		print ('    WIF:', utils.base58encode(utils.base256decode( result )))
		print ('    WIF:', keyUtils.privateKeyToWif( private_key , net=net, compressed='yes'))
		print ('    WIF:', keyUtils.privateKeyToWif( private_key , net=net, compressed='no'))
*/
	}

}
