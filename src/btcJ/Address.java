package btcJ;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;

import org.apache.commons.codec.DecoderException;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

public class Address {

	public static byte[] wifToPrivateKey(String string) {

		String wif = string;

		byte[] wif_enc  = new byte[ wif.length() ];

		wif_enc = Base58.decode(wif);

		byte[] wif_enc_fin = new byte[ wif_enc.length-5];

		//Drop first and last four bytes
		System.arraycopy(wif_enc, 1, wif_enc_fin, 0, wif_enc.length - 5);
		return( wif_enc_fin);
	}

	public static byte[] wifChecksum(String string) {

		byte[] wif_enc = Base58.decode(string);
		byte[] wif_enc_sh = new byte[ wif_enc.length-4];

		System.arraycopy(wif_enc, 0, wif_enc_sh, 0, wif_enc.length - 4);

		byte[] hash = new byte[256];
		byte[] hash2 = new byte[256];
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			hash = digest.digest(wif_enc_sh);
			hash2 = digest.digest(hash);


		} catch (Exception e) {
			// TODO: handle exception
		}
		byte[] checksum = new byte[4];
		System.arraycopy(hash2, 0, checksum, 0, checksum.length );
		return(checksum);
	}

	public static byte[] privateKeyToWif(String string, boolean testnet) {

		string = testnet ? "EF" + string : "80" + string;

		byte[] privateKeyBytes = new byte[string.length()];
		byte[] checksum = new byte[4];
		try {
			privateKeyBytes = org.apache.commons.codec.binary.Hex.decodeHex(string.toCharArray());
		} catch (DecoderException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		byte[] hash = new byte[256];
		byte[] hash2 = new byte[256];
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			hash = digest.digest(privateKeyBytes);
			hash2 = digest.digest(hash);


		} catch (Exception e) {
			// TODO: handle exception
		}





		System.arraycopy(hash2, 0, checksum, 0, checksum.length );

		byte[] combined = new byte[privateKeyBytes.length + checksum.length];

		for (int i = 0; i < combined.length; ++i)
		{
			combined[i] = i < privateKeyBytes.length ? privateKeyBytes[i] : checksum[i - privateKeyBytes.length];
		}

		return(combined);
	}

	public static byte[] privateKeyToAddress(String private_key, boolean testnet, boolean compressed) {




		byte[] publicKeyBytes = privateKeyToPublicKey(private_key, compressed);
		System.out.println(Utils.toHex(publicKeyBytes));
		System.out.println(publicKeyBytes.length);
		byte[] out = new byte[20];
		byte[] hash = new byte[256];
		byte[] hash2 = new byte[256];

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





		byte[] ripemd_bytes = null;
		byte[] checksum = new byte[4];

		try {
			ripemd_bytes = org.apache.commons.codec.binary.Hex.decodeHex(("00" + Utils.toHex(out).toUpperCase()).toCharArray());
		} catch (DecoderException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}


		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			hash = digest.digest(ripemd_bytes);
			hash2 = digest.digest(hash);

		} catch (Exception e) {
			// TODO: handle exception
		}


		System.arraycopy(hash2, 0, checksum, 0, checksum.length );
		byte[] combined = new byte[1 + out.length + checksum.length];

		for (int i = 0; i < combined.length; ++i)
		{
			combined[i] = i < ripemd_bytes.length ? ripemd_bytes[i] : checksum[i - ripemd_bytes.length];
		}
		System.out.println(Utils.toHex(combined));
		return(combined);
	}

	public static byte[] privateKeyToPublicKey(String private_key,
			boolean compressed) {
		byte[] privateKeyBytes = null;

		try {
			privateKeyBytes = org.apache.commons.codec.binary.Hex.decodeHex(private_key.toCharArray());
		} catch (DecoderException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		

		X9ECParameters ecp = SECNamedCurves.getByName("secp256k1");
		ECDomainParameters domainParams = new ECDomainParameters(ecp.getCurve(),
				ecp.getG(), ecp.getN(), ecp.getH(),
				ecp.getSeed());

		ECPrivateKeyParameters privateKey = new ECPrivateKeyParameters(new BigInteger(1,privateKeyBytes), domainParams) ;
		System.out.println(privateKey.getD());
		byte[] publicKeyBIBytes = privateKey.getD().toByteArray();
		ECPoint Q = domainParams.getG().multiply(new BigInteger(publicKeyBIBytes));





		byte[] publicKeyBytes = Q.getEncoded(compressed);
		return publicKeyBytes;
	}

	public static byte[] publicKeyToAddress(String string) {

		byte[] publicKeyBytes = null;

		try {
			publicKeyBytes = org.apache.commons.codec.binary.Hex.decodeHex( string.toCharArray() ) ;
		} catch (DecoderException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		//System.out.println(Utils.toHex(publicKeyBytes));
		//System.out.println(publicKeyBytes.length);
		byte[] out = new byte[20];
		byte[] hash = new byte[256];
		byte[] hash2 = new byte[256];

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





		byte[] ripemd_bytes = null;
		byte[] checksum = new byte[4];

		try {
			ripemd_bytes = org.apache.commons.codec.binary.Hex.decodeHex(("00" + Utils.toHex(out).toUpperCase()).toCharArray());
		} catch (DecoderException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}


		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			hash = digest.digest(ripemd_bytes);
			hash2 = digest.digest(hash);

		} catch (Exception e) {
			// TODO: handle exception
		}


		System.arraycopy(hash2, 0, checksum, 0, checksum.length );
		byte[] combined = new byte[1 + out.length + checksum.length];

		for (int i = 0; i < combined.length; ++i)
		{
			combined[i] = i < ripemd_bytes.length ? ripemd_bytes[i] : checksum[i - ripemd_bytes.length];
		}

		//System.out.println(Utils.toHex(combined));
		return(combined);
	}

	public static byte[] addrHashToScriptPubKey(String string) throws DecoderException {
		// TODO Auto-generated method stub
	    //return b'76a914' + codecs.encode(utils.base58CheckDecode(b58str),'hex')  + b'88ac'

		return org.apache.commons.codec.binary.Hex.decodeHex (("76a914" + Utils.toHex(Base58Check.decode(string)) + "88ac").toCharArray()) ;
	}
	
	public static ECPrivateKey WIFtoECPrivateKey(String wif) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException{
        byte [] privateKey = Address.wifToPrivateKey("5Kb6aGpijtrb8X28GzmWtbcGZCG8jHQWFJcWugqo3MwKRvC8zyu");

		KeyPairGenerator kpg = null;
		kpg = KeyPairGenerator.getInstance("EC");
	
	ECGenParameterSpec gps = new ECGenParameterSpec ("secp256k1"); // NIST P-256 
	kpg.initialize(gps);
	KeyPair apair = kpg.generateKeyPair(); 
	ECPublicKey apub  = (ECPublicKey)apair.getPublic();
	ECParameterSpec aspec = apub.getParams();
	// could serialize aspec for later use (in compatible JRE)
	//
	// for test only reuse bogus pubkey, for real substitute values 
	KeyFactory kfa = null;
	kfa = KeyFactory.getInstance ("EC");
	ECPrivateKey bpriv = null;
	ECPrivateKeySpec pkeys = new ECPrivateKeySpec(new BigInteger(1,privateKey), aspec);
	
	return bpriv = (ECPrivateKey) kfa.generatePrivate(pkeys);

	}

}
