package btcJ;


import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;

import org.apache.commons.codec.DecoderException;

import sun.security.ec.*;

public class VerifySignatureSunEC2 {

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException, DecoderException {
		// TODO Auto-generated method stub
		String txn =          ("0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000" +
				"8a47" +
				"304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac01" +
				"41" +
				"04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55" +
				"ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000" +
				"1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000");

		String [] parsed = Transaction.parseTransaction(txn);
		
		String derSig = parsed[1].substring(0, parsed[1].length()-2);
		byte [] signableTxn = Transaction.getSignableTransaction(parsed);
		
		//System.out.println(Utils.toHex(signableTxn));
		
		byte[] hash = new byte[256];
		byte[] hashtosign = new byte[256];

		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			hash = digest.digest(signableTxn);
			hashtosign = digest.digest(hash);
		} catch (Exception e) {
			// TODO: handle exception
		}

		byte [] pubKeyBytes = new byte[65];
		
		byte [] sigBytes = null;
			pubKeyBytes = org.apache.commons.codec.binary.Hex.decodeHex(parsed[2].substring(0).toCharArray());
			sigBytes = org.apache.commons.codec.binary.Hex.decodeHex(derSig.toCharArray());
			//pubKeyBytes = org.apache.commons.codec.binary.Hex.decodeHex(derSig.substring(2).toCharArray());
		byte[] sigt = new byte[40];
		sigt = Transaction.decodeFromDER(sigBytes);
		
		// generate bogus keypair(!) with named-curve params
		KeyPairGenerator kpg = null;
		try {
			kpg = KeyPairGenerator.getInstance("EC");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		ECGenParameterSpec gps = new ECGenParameterSpec ("secp256k1"); // NIST P-256 
		kpg.initialize(gps);
		KeyPair apair = kpg.generateKeyPair(); 
		ECPublicKey apub  = (ECPublicKey)apair.getPublic();
		ECParameterSpec aspec = apub.getParams();
		// could serialize aspec for later use (in compatible JRE)
		//
		// for test only reuse bogus pubkey, for real substitute values 
		ECPoint apoint = apub.getW();
		BigInteger x = apoint.getAffineX(), y = apoint.getAffineY();
		x = new BigInteger(org.apache.commons.codec.binary.Hex.decodeHex("392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab73".toCharArray()));
		y = new BigInteger(org.apache.commons.codec.binary.Hex.decodeHex("9f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55".toCharArray()));
		sigt = org.apache.commons.codec.binary.Hex.decodeHex("304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac01".toCharArray());
		sigt = org.apache.commons.codec.binary.Hex.decodeHex("3044022000c7adaed7bed837fa6d0c1c7ec9a8ae41d5f5a85d3890c56413446af20d3e1e022018231537b6f431629b2304083a139f62431c1f4fc9a1552a4c9fa2a87d1b6e9c".toCharArray());
		x = new BigInteger("392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab73",16);
		y = new BigInteger("9f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55",16);
		// construct point plus params to pubkey
		ECPoint bpoint = new ECPoint (x,y); 
		ECPublicKeySpec bpubs = new ECPublicKeySpec (bpoint, aspec);
		KeyFactory kfa = null;
		kfa = KeyFactory.getInstance ("EC");
		ECPublicKey bpub = null;
		bpub = (ECPublicKey) kfa.generatePublic(bpubs);
		System.out.println(bpub.toString());
		System.out.println(bpub.getW().getAffineX());
		System.out.println(bpub.getW().getAffineY());
		//
		// for test sign with original key, verify with reconstructed key
		Signature sig = null;
		sig = Signature.getInstance ("SHA256withECDSA");
		//dsig = sig.sign();
		//sig.update(hashtosign);
		sig.initVerify(bpub);
		sig.update(hashtosign);
		System.out.println(Utils.toHex(sigt) + "  length:" + sigt.length);
		System.out.println (sig.verify(sigt));

		

	}

}
