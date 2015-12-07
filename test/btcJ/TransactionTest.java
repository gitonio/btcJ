package btcJ;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

import org.apache.commons.codec.DecoderException;
import org.junit.Test;

public class TransactionTest {

	@Test
	public void parseTransaction() {
		String txn =          ("0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000" +
				"8a47" +
				"304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac01" +
				"41" +
				"04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55" +
				"ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000" +
				"1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000");
		String[] parsed = Transaction.parseTransaction(txn);
		assertEquals(parsed[0], "0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000");
		assertEquals(parsed[1], "304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac01");
		assertEquals(parsed[2], "04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55");
		assertEquals(parsed[3], "ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e0000000000001976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000");
	}

	@Test
	public void getSignableTransaction() {
		String txn =          ("0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000" +
				"8a47" +
				"304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac01" +
				"41" +
				"04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55" +
				"ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000" +
				"1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000");
		String[] parsed = Transaction.parseTransaction(txn);
		byte [] stn = Transaction.getSignableTransaction(parsed);
		String myTxn_forSig = ("0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000" +
				"1976a914" + "167c74f7491fe552ce9e1912810a984355b8ee07" + "88ac" +
				"ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000" +
				"1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000" +
				"01000000");
		byte [] signableTxn = Transaction.getSignableTransaction(parsed);
		assertEquals(Utils.toHex(signableTxn), myTxn_forSig);
	}
	
	@Test
	public void verifyTransaction(){
		String txn =          ("0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000" +
				"8a47" +
				"304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac01" +
				"41" +
				"04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55" +
				"ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000" +
				"1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000");
		try {
			Transaction.verifyTransaction(txn);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	@Test
	public void verifyTransaction2(){
		String txn =          ("0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000" +
				"8a47" +
				"304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac01" +
				"41" +
				"04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55" +
				"ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000" +
				"1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000");
		try {
			Transaction.verifyTransaction2(txn);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@Test
	public void decodeFromDER(){
        String derSig = "304502204c01fee2d724fb2e34930c658f585d49be2f6ac87c126506c0179e6977716093022100faad0afd3ae536cfe11f83afaba9a8914fc0e70d4c6d1495333b2fb3df6e8cae";
        assertEquals("4c01fee2d724fb2e34930c658f585d49be2f6ac87c126506c0179e6977716093faad0afd3ae536cfe11f83afaba9a8914fc0e70d4c6d1495333b2fb3df6e8cae",
        		Transaction.decodeFromDER(derSig));

	}
	
	@Test
	public void makeRawTransaction() throws IOException, DecoderException{
        ArrayList<IOPuts> aList = new ArrayList<IOPuts>();
        aList.add(new IOPuts(99900000, Address.addrHashToScriptPubKey("1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa") ));
        aList.add(new IOPuts(2000,  Address.addrHashToScriptPubKey("15nhZbXnLMknZACbb3Jrf1wPCD9DWAcqd7") ));
        String txn = Transaction.makeRawTransaction(
                "f2b3eb2deb76566e7324307cd47c35eeb88413f971d88519859b1834307ecfec", //# output transaction hash
                1, //# sourceIndex
                "76a914010966776006953d5567439e5e39f86a0d273bee88ac",// # scriptSig
                99900000, //#satoshis
                "76a914097072524438d003d23a2f23edb65aae1bb3e46988ac"  //# outputScript
                ) + "01000000" ;//# hash code type
        assertEquals(
                "0100000001eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2" +
                "010000001976a914010966776006953d5567439e5e39f86a0d273bee88acffffffff" +
                "01605af405000000001976a914097072524438d003d23a2f23edb65aae1bb3e46988ac" +
                "0000000001000000",txn);


	}
	
	@Test
	public void makeRawTransaction2() throws IOException, DecoderException{
		String outputTransactionHash = "76a914097072524438d003d23a2f23edb65aae1bb3e46988ac";
        ArrayList<IOPuts> outputs = new ArrayList<IOPuts>();
        outputs.add(new IOPuts(99900000, org.apache.commons.codec.binary.Hex.decodeHex(outputTransactionHash.toCharArray())));
 
        String txn = Transaction.makeRawTransaction2(
                "f2b3eb2deb76566e7324307cd47c35eeb88413f971d88519859b1834307ecfec", //# output transaction hash
                1, //# sourceIndex
                "76a914010966776006953d5567439e5e39f86a0d273bee88ac",// # scriptSig
                outputs
                ) + "01000000" ;//# hash code type
        assertEquals(
                "0100000001eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2" +
                "010000001976a914010966776006953d5567439e5e39f86a0d273bee88acffffffff" +
                "01605af405000000001976a914097072524438d003d23a2f23edb65aae1bb3e46988ac" +
                "0000000001000000",txn);


	}

	
	
	@Test
	public void makeSignedTransaction() throws DecoderException, IOException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, NoSuchProviderException {
        byte [] privateKey = Address.wifToPrivateKey("5Kb6aGpijtrb8X28GzmWtbcGZCG8jHQWFJcWugqo3MwKRvC8zyu");
		String txn =          ("0100000001a97830933769fe33c6155286ffae34db44c6b8783a2d8ca52ebee6414d399ec300000000" +
				"8a47" +
				"304402202c2e1a746c556546f2c959e92f2d0bd2678274823cc55e11628284e4a13016f80220797e716835f9dbcddb752cd0115a970a022ea6f2d8edafff6e087f928e41baac01" +
				"41" +
				"04392b964e911955ed50e4e368a9476bc3f9dcc134280e15636430eb91145dab739f0d68b82cf33003379d885a0b212ac95e9cddfd2d391807934d25995468bc55" +
				"ffffffff02015f0000000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac204e000000000000" +
				"1976a914348514b329fda7bd33c7b2336cf7cd1fc9544c0588ac00000000");
      
        ArrayList<IOPuts> aList = new ArrayList<IOPuts>();
        aList.add(new IOPuts(24321, Address.addrHashToScriptPubKey("1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa") ));
        aList.add(new IOPuts(2000,  Address.addrHashToScriptPubKey("15nhZbXnLMknZACbb3Jrf1wPCD9DWAcqd7") ));
        		
       String  signed_txn = Transaction.makeSignedTransaction(privateKey,
            "c39e394d41e6be2ea58c2d3a78b8c644db34aeff865215c633fe6937933078a9", //# output (prev) transaction hash
            0, //# sourceIndex
            Address.addrHashToScriptPubKey("133txdxQmwECTmXqAr9RWNHnzQ175jGb7e"),
            aList
    		   );
       System.out.println("signed_txn:" + signed_txn);
       //assertEquals(txn, signed_txn);
		Transaction.verifyTransaction2(signed_txn);

	}

}
