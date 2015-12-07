package btcJ;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Iterator;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;
import org.bitcoinj.core.ECKey;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

public class Transaction {


	public static byte [] decodeFromDER(byte[] bytes) {
		ASN1InputStream decoder = null;
		try {
			decoder = new ASN1InputStream(bytes);

			DLSequence seq = (DLSequence) decoder.readObject();
			if (seq == null)
				throw new RuntimeException("Reached past end of ASN.1 stream.");
			ASN1Integer r, s;
			try {
				r = (ASN1Integer) seq.getObjectAt(0);
				s = (ASN1Integer) seq.getObjectAt(1);

			} catch (ClassCastException e) {
				throw new IllegalArgumentException(e);
			}

			System.out.println("r:  "+Utils.toHex(r.getEncoded()));
			System.out.println("s:  "+Utils.toHex(s.getEncoded()));
			System.out.println("r:  "+r.getPositiveValue());
			System.out.println("s:  "+s.getPositiveValue());
			//byte[] x = new byte[r.getEncoded().length -2];
			//byte[] y = new byte[s.getEncoded().length - 2];
			byte[] x = new byte[36];
			byte[] y = new byte[34];
			byte[] xy = new byte[x.length + y.length];
			System.arraycopy(r.getEncoded(), 2, x, 4, r.getEncoded().length -2);
			System.arraycopy(s.getEncoded(), 2, y, 2, s.getEncoded().length - 2);
			System.arraycopy(x, 0, xy, 0, x.length);
			System.arraycopy(y, 0, xy, x.length  , y.length);
			System.out.println("xy    "+ Utils.toHex(xy));
			return xy;
		} catch (IOException e) {
			throw new RuntimeException(e);
		} finally {
			if (decoder != null)
				try { decoder.close(); } catch (IOException x) {}
		}
	}

	public static String decodeFromDER(String string) {
		ASN1InputStream decoder = null;
		try {
			byte [] bytes = null;
			try {
				bytes = org.apache.commons.codec.binary.Hex.decodeHex( string.toCharArray() ) ;
			} catch (DecoderException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			decoder = new ASN1InputStream(bytes);

			DLSequence seq = (DLSequence) decoder.readObject();
			if (seq == null)
				throw new RuntimeException("Reached past end of ASN.1 stream.");
			ASN1Integer r, s;
			try {
				r = (ASN1Integer) seq.getObjectAt(0);
				s = (ASN1Integer) seq.getObjectAt(1);

			} catch (ClassCastException e) {
				throw new IllegalArgumentException(e);
			}
			// OpenSSL deviates from the DER spec by interpreting these values as unsigned, though they should not be
			// Thus, we always use the positive versions. See: http://r6.ca/blog/20111119T211504Z.html

			//System.out.println(Utils.toHex(r.getEncoded()));
			//System.out.println(Utils.toHex(s.getEncoded()));
			Base64.encodeInteger(r.getValue());
			Base64.encodeInteger(s.getPositiveValue());





			byte[] x = new byte[r.getEncoded().length-2 ];
			byte[] y = new byte[s.getEncoded().length -3];
			byte[] xy = new byte[x.length + y.length];

			System.arraycopy(r.getEncoded(), 2, x, 0, r.getEncoded().length-2 );
			System.out.println("x:"+Utils.toHex(x));
			System.arraycopy(s.getEncoded(), 3, y, 0, s.getEncoded().length-3 );
			//System.out.println("y:"+Utils.toHex(y));
			System.arraycopy(x, 0, xy, 0, x.length);
			System.arraycopy(y, 0, xy, x.length  , y.length);
			System.out.println("xy    "+ Utils.toHex(xy));
			return Utils.toHex(xy);
		} catch (IOException e) {
			throw new RuntimeException(e);
		} finally {
			if (decoder != null)
				try { decoder.close(); } catch (IOException x) {}
		}
	}




	public static String [] parseTransaction(String txn) {
		// TODO Auto-generated method stub
		System.out.println("Parse input txn:" +txn);
		byte [] outbytes = new byte [2];
		/*	    first = txn[0:41*2]
	    	    scriptLen = int(txn[41*2:42*2], 16)
	    	    script = txn[42*2:42*2+2*scriptLen]
	    	    sigLen = int(script[0:2], 16)
	    	    sig = script[2:2+sigLen*2]
	    	    pubLen = int(script[2+sigLen*2:2+sigLen*2+2], 16)
	    	    pub = script[2+sigLen*2+2:]

	    	    assert(len(pub) == pubLen*2)
	    	    rest = txn[42*2+2*scriptLen:]
	    	    return [first, sig, pub, rest]         
		 */
		String first = txn.substring(0, 41*2);
		int scriptlen = Integer.parseInt(txn.substring(41*2, 42*2),16);
		String script = txn.substring(42*2, 42*2+ 2*scriptlen);
		int siglen = Integer.parseInt(script.substring(0, 2),16);
		String sig = script.substring(2, 2+siglen*2);
		int publen = Integer.parseInt(script.substring(2+siglen*2, 2+siglen*2+2), 16);
		String pub = script.substring(2+siglen*2+2);
		String rest = txn.substring(42*2+2*scriptlen);

		String[] parsed = new String[] {first,sig,pub,rest} ;
		System.out.println("Parse first" + first);
		System.out.println("Parse sig" + sig);
		System.out.println("Parse pub" + pub);
		return parsed;
	}

	public static byte[] getSignableTransaction(String[] parsed) {
		// TODO Auto-generated method stub
		/*	    first, sig, pub, rest = parsed
	    	    #inputAddr = utils.base58CheckDecode(keyUtils.pubKeyToAddr(pub.decode()))
	    	    print('first: ', first, 'sig: ', sig, 'pub: ', pub, 'rest: ', rest)
	    	    #if (compressed=='yes'):
	    	    #    inputAddr = codecs.encode(utils.base58CheckDecode(keyUtils.pubKeyToAddr('03' +  pub[2:66],net= 'test', compressed='yes')),'hex').decode()
	    	    #    print('pubk  ','03' +  pub[2:66] )
	    	    #else:
	    	    #    inputAddr = codecs.encode(utils.base58CheckDecode(keyUtils.pubKeyToAddr(pub)),'hex').decode()
	    	    inputAddr = codecs.encode(utils.base58CheckDecode(keyUtils.pubKeyToAddr(pub)),'hex').decode()

	    	    #inputAddr = codecs.encode(utils.base58CheckDecode('moyDyvi7VeAhZnGEWtvE62PoDdmoRXRRkf'),'hex').decode()
	    	    print('pub uncompressed: ', keyUtils.pubKeyToAddr(pub,net='test'))
	    	    print('pub   compressed: ', keyUtils.pubKeyToAddr('03' + pub[2:66],net='test'))
	    	    print("inputAddr:", keyUtils.pubKeyToAddr('02' +pub[2:66],net= 'test'))
	    	    print('a:', codecs.encode(utils.base58CheckDecode('1MMMMSUb1piy2ufrSguNUdFmAcvqrQF8M5'),'hex').decode())
	    	    print('b:', codecs.encode(utils.base58CheckDecode('muwc2rRij1XuJZ5JqsevtjCvqMw9CenJfK'),'hex').decode())
	    	    print("inputAddr:", inputAddr)
	    	    #inputAddr = 'msZwQEA3dYTXDEUjHgfXkGSkLXpfEpLZEA'
	    	    #print(codecs.encode(inputAddr,'hex').decode())
	    	    #return first + "1976a914" + inputAddr.encode('hex') + "88ac" + rest + "01000000"
	    	    return first.encode('utf-8') + b"1976a914" + inputAddr.encode('utf-8') + b"88ac" + rest.encode('utf-8') + b"01000000"
		 */	
		String first = 	parsed[0];
		String sig = 	parsed[1];
		String pub = 	parsed[2];
		String rest = 	parsed[3];
		//System.out.println("address" + Base58Check.decode( Address.publicKeyToAddress(pub) ));
		String inputAddr = Base58.encode(Address.publicKeyToAddress(pub));
		//System.out.println("1addr " + inputAddr);
		byte[] inputAddr2 = Base58Check.decode(inputAddr);
		inputAddr = Utils.toHex(inputAddr2);
		//System.out.println("2addr " + inputAddr);
		String inp = first + "1976a914" + inputAddr + "88ac" + rest + "01000000";
		byte [] rv = null;
		try {
			rv = org.apache.commons.codec.binary.Hex.decodeHex( inp.toCharArray() ) ;
		} catch (DecoderException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}


		return rv;	

	}

	public static void verifyTransaction(String txn) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, SignatureException, InvalidKeyException {
		// TODO Auto-generated method stub
		/*	    print('txn:', txn)            
	    parsed = parseTxn(txn)     
	    print('parsed: ', parsed) 
	    compressed=compressed
	    print('compressed vts:', compressed)
	    signableTxn = getSignableTxn(parsed, compressed=compressed)
	    print('SignableTxn:', signableTxn)
	    hashToSign = hashlib.sha256(hashlib.sha256(codecs.decode(signableTxn,'hex')).digest()).digest()
	    assert(parsed[1][-2:] == '01') # hashtype
	    sig = keyUtils.derSigToHexSig(parsed[1][:-2])
	    if (compressed=='no'):
	        public_key = parsed[2]
	    else:
	        public_key = pubk
	    print('public_key: ', public_key)
	    print('sig :', sig.encode('utf-8'))
	    vk = ecdsa.VerifyingKey.from_string(codecs.decode(public_key[2:].encode('utf-8'),'hex'), curve=ecdsa.SECP256k1)
	    #print(vk.verify_digest(codecs.decode(sig.encode('utf-8'),'hex'), hashToSign ))
	    assert(vk.verify_digest(codecs.decode(sig.encode('utf-8'),'hex'), hashToSign ))
		 */	
		String [] parsed = parseTransaction(txn);
		byte [] signableTxn = getSignableTransaction(parsed);
		//System.out.println(Utils.toHex(signableTxn));

		String myTxn_forSig = ("0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000" +
				"1976a914" + "167c74f7491fe552ce9e1912810a984355b8ee07" + "88ac" +
				"ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000" +
				"1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000" +
				"01000000");
		System.out.println(myTxn_forSig.equalsIgnoreCase(Utils.toHex(signableTxn)));
		//System.out.println(parsed[2]);
		System.out.println(parsed[2].equalsIgnoreCase("04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55"));
		byte[] hash = new byte[256];
		byte[] hashtosign = new byte[256];
		byte[] sig = new byte[40];

		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			hash = digest.digest(signableTxn);
			hashtosign = digest.digest(hash);
		} catch (Exception e) {
			// TODO: handle exception
		}
		assert parsed[1].substring(parsed[1].length()-2)=="01";
		System.out.println("hashtosign     " + Utils.toHex(hashtosign));
		//System.out.println(parsed[1].substring(parsed[1].length()-2));
		//String derSig =   "304502204c01fee2d724fb2e34930c658f585d49be2f6ac87c126506c0179e6977716093022100faad0afd3ae536cfe11f83afaba9a8914fc0e70d4c6d1495333b2fb3df6e8cae";
		//String derSig = "04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55";
		//String derSig = "2c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f8797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac";
		String derSig = parsed[1].substring(0, parsed[1].length()-2);
		System.out.println("derSig    "+derSig);
		byte [] pubKeyBytes = new byte[65];
		byte[] pkb = new byte [65];
		byte [] sigBytes = null;
		try {
			pubKeyBytes = org.apache.commons.codec.binary.Hex.decodeHex(parsed[2].substring(0).toCharArray());
			sigBytes = org.apache.commons.codec.binary.Hex.decodeHex(derSig.toCharArray());
			//pubKeyBytes = org.apache.commons.codec.binary.Hex.decodeHex(derSig.substring(2).toCharArray());
		} catch (DecoderException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		sig = decodeFromDER(sigBytes);

		System.out.println("Sigder        " + Utils.toHex(sigBytes) +"  length:" + sigBytes.length);
		System.out.println("Sig           " + Utils.toHex(sig) +"  length:" + sig.length);
		System.out.println("Pub Key   "+Utils.toHex(pubKeyBytes) +"  length:" + pubKeyBytes.length);
		System.arraycopy(pubKeyBytes, 0, pkb, 0, pubKeyBytes.length);
		System.out.println("Pub Key   "+Utils.toHex(pkb) +"  length:" + pkb.length);
		//KeyPair pair = GenerateKeys();

		ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
		KeyFactory kf = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
		ECNamedCurveSpec params = new ECNamedCurveSpec("secp256k1", spec.getCurve(), spec.getG(), spec.getN());
		ECPoint point =  ECPointUtil.decodePoint(params.getCurve(), pkb);
		ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
		ECPublicKey pk = (ECPublicKey) kf.generatePublic(pubKeySpec);


		Signature           signature = Signature.getInstance("ECDSA", "BC");
		//signature.
		System.out.println(pk.toString());

		// generate a signature
		//signature.initSign(keyPair.getPrivate(), Utils.createFixedRandom());

		//signature.update(hashtosign);

		// verify a signature

		signature.initVerify(pk);

		signature.update(hashtosign);
		//byte[]  sigBytes = signature.sign();

		if (signature.verify((sigBytes)))
		{
			System.out.println("signature verification succeeded.");
		}
		else
		{
			System.out.println("signature verification failed.");
		}
		ECKey e =  ECKey.fromPublicOnly(pkb) ;
		System.out.println(e.getPublicKeyAsHex());
		boolean tf = e.verify(hashtosign, sigBytes,  e.getPubKey());
		System.out.println(tf);
	}

	public static void verifyTransaction2(String txn) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, SignatureException, InvalidKeyException {
		String [] parsed = parseTransaction(txn);
		byte [] signableTxn = getSignableTransaction(parsed);
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

		String derSig = parsed[1].substring(0, parsed[1].length()-2);
		System.out.println("derSig:" + derSig + " length:" + derSig.length());
		byte [] pubKeyBytes = new byte[65];
		byte[] pkb = new byte [65];
		byte [] sigBytes = null;
		
		try {
			System.out.println("Parsed2 : " + parsed[2]);
			pubKeyBytes = org.apache.commons.codec.binary.Hex.decodeHex(parsed[2].substring(0).toCharArray());
			sigBytes = org.apache.commons.codec.binary.Hex.decodeHex(derSig.toCharArray());
			//pubKeyBytes = org.apache.commons.codec.binary.Hex.decodeHex(derSig.substring(2).toCharArray());
		} catch (DecoderException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		System.out.println("Pub Key   "+Utils.toHex(pubKeyBytes) +"  length:" + pubKeyBytes.length);
		//System.arraycopy(pubKeyBytes, 0, pkb, 0, pubKeyBytes.length);

		ECKey e =  ECKey.fromPublicOnly(pubKeyBytes) ;
		System.out.println(e.getPubKeyPoint().getAffineXCoord().toString());
		System.out.println(e.getPubKeyPoint().getAffineYCoord().toString());
		System.out.println(Utils.toHex( e.getPubKey()));
		System.out.println(e.getPubKeyPoint().getAffineXCoord().toBigInteger());
		System.out.println(e.getPubKeyPoint().getAffineYCoord().toBigInteger());
		boolean tf = ECKey.verify(hashtosign, sigBytes,  e.getPubKey());
		if (tf)
		{
			System.out.println("signature verification succeeded.");
		}
		else
		{
			System.out.println("signature verification failed.");
		}
	}

	public static String makeRawTransaction(String outputTransactionHash, int sourceIndex,
			String scriptSig, int satoshis, String outputScript) throws IOException, DecoderException {
		// TODO Auto-generated method stub
		StringBuilder sb = new StringBuilder();

		String fi = "0100000001";
		sb.append(fi);

		byte [] ba = org.apache.commons.codec.binary.Hex.decodeHex(outputTransactionHash.toCharArray());
		ArrayUtils.reverse(ba);
		sb.append(Utils.toHex(ba));

		ByteArrayOutputStream b = new ByteArrayOutputStream();
		DataOutputStream d = new DataOutputStream(b);
		d.writeInt(sourceIndex);
		byte[] result = b.toByteArray();
		ArrayUtils.reverse(result);
		sb.append(Utils.toHex(result));


		//System.out.println("length");
		sb.append(Integer.toHexString(scriptSig.length()/2));
		ba = org.apache.commons.codec.binary.Hex.decodeHex(scriptSig.toCharArray());
		sb.append(Utils.toHex(ba));
		sb.append("ffffffff01");





		b = new ByteArrayOutputStream();
		d = new DataOutputStream(b);
		d.writeLong(satoshis);
		result = b.toByteArray();
		ArrayUtils.reverse(result);
		//System.out.println(Utils.toHex(result));
		sb.append(Utils.toHex(result));



		sb.append(Integer.toHexString(outputScript.length()/2));
		ba = org.apache.commons.codec.binary.Hex.decodeHex(outputScript.toCharArray());
		sb.append(Utils.toHex(ba));
		
		
		sb.append("00000000");

		//System.out.println(sb);
		return sb.toString();
	}
	
	
	public static String makeRawTransaction2(String outputTransactionHash, int sourceIndex,
			String scriptSig,  ArrayList<IOPuts> outputs) throws IOException, DecoderException {
		// TODO Auto-generated method stub
		// TODO Auto-generated method stub
		StringBuilder sb = new StringBuilder();

		String fi = "0100000001";
		sb.append(fi);

		byte [] ba = org.apache.commons.codec.binary.Hex.decodeHex(outputTransactionHash.toCharArray());
		ArrayUtils.reverse(ba);
		sb.append(Utils.toHex(ba));

		ByteArrayOutputStream b = new ByteArrayOutputStream();
		DataOutputStream d = new DataOutputStream(b);
		d.writeInt(sourceIndex);
		byte[] result = b.toByteArray();
		ArrayUtils.reverse(result);
		sb.append(Utils.toHex(result));


		//System.out.println("length");
		sb.append(Integer.toHexString(scriptSig.length()/2));
		System.out.println("script sig length:"+ Integer.toHexString(scriptSig.length()/2));
		ba = org.apache.commons.codec.binary.Hex.decodeHex(scriptSig.toCharArray());
		sb.append(Utils.toHex(ba));
		sb.append("ffffffff");
		//Number of outputs
		sb.append(String.format("%02X", outputs.size()));

		for (Iterator iterator = outputs.iterator(); iterator.hasNext();) {
			IOPuts ioPuts = (IOPuts) iterator.next();
			
		
		


		b = new ByteArrayOutputStream();
		d = new DataOutputStream(b);
		d.writeLong(ioPuts.satoshis);
		result = b.toByteArray();
		ArrayUtils.reverse(result);
		//System.out.println(Utils.toHex(result));
		sb.append(Utils.toHex(result));



		sb.append(Integer.toHexString(Utils.toHex(ioPuts.scriptPubKey).length()/2));
		System.out.println("scriptPubKey Length:"+Integer.toHexString(Utils.toHex(ioPuts.scriptPubKey).length()/2));
		//ba = org.apache.commons.codec.binary.Hex.decodeHex(outputScript.toCharArray());
		sb.append(Utils.toHex(ioPuts.scriptPubKey));
	}
		
		sb.append("00000000");

		//System.out.println(sb);
		return sb.toString();
	}


	public static String makeSignedTransaction(byte[] privateKey,
			String outputTransactionHash, int sourceIndex, byte[] scriptPubKey,
			ArrayList<IOPuts> outputs) throws DecoderException, IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
		// TODO Auto-generated method stub
		String  myTxn_forSig = (makeRawTransaction2(outputTransactionHash, sourceIndex, Utils.toHex(scriptPubKey), outputs)
				+ "01000000"); // # hash code

		byte [] myTxn_forSig_ba = org.apache.commons.codec.binary.Hex.decodeHex(myTxn_forSig.toCharArray());

		byte[] hash = new byte[256];
		byte[] s256 = new byte[256];

		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		hash = digest.digest(myTxn_forSig_ba);
		s256 = digest.digest(hash);



		ECPrivateKey bpriv = Address.PrivateKeytoECPrivateKey(privateKey);
		//System.out.println(bpriv.getS());
		//System.out.println(new BigInteger(1,privateKey));
		//
		// for test sign with original key, verify with reconstructed key
		Signature sig = null;
		sig = Signature.getInstance ("SHA256withECDSA");
		sig.initSign(bpriv);
		sig.update (s256);
		byte[] dsig = null;
		dsig = sig.sign();
		//System.out.println(sig.hashCode());
		System.out.println(Utils.toHex(dsig) + "  length:" + dsig.length);

		ECPublicKey cpub = Address.PrivateKeytoECPublicKey(privateKey);

		System.out.println(cpub.getFormat());
		System.out.println("public key: " + Utils.toHex(Address.privateKeyToPublicKey(Utils.toHex(privateKey), false)));
		
		
		sig.initVerify(cpub);
		sig.update(s256);
		System.out.println(sig.getProvider());
		System.out.println (sig.verify(dsig));
		byte[] dsig2 = new byte [dsig.length+1];
		
		byte[] dsig3 = new byte [1];
		dsig3[0] = 0x01;
		System.arraycopy(dsig, 0, dsig2, 0, dsig.length);
		System.arraycopy(dsig3,0,dsig2,dsig2.length-1, 1);
		
		//Utils.Utils.varstr(dsig)
		//String scriptSig = Utils.toHex(Utils.varstr(dsig)) + Utils.toHex(Address.privateKeyToPublicKey(Utils.toHex(privateKey), false));
		String scriptSig = Utils.toHex(Utils.varstr(dsig2)) + Utils.toHex(Utils.varstr(Address.privateKeyToPublicKey(Utils.toHex(privateKey), false)));
		System.out.println("scriptSig:" + scriptSig);
	    //scriptSig = codecs.encode(utils.varstr(sig),'hex').decode() + codecs.encode(utils.varstr(pubKey),'hex').decode()
	    	//    signed_txn = makeRawTransaction(outputTransactionHash, sourceIndex, scriptSig, outputs)
		String signed_txn = makeRawTransaction2(outputTransactionHash, sourceIndex, scriptSig, outputs);
	    	  //  print('compressed mst:',compressed)
	    	   // verifyTxnSignature(signed_txn.decode(),compressed=compressed, pubk=pubKey2)
		System.out.println("myTxn_forSig:" + myTxn_forSig);
	    	    return signed_txn;

	}


}
