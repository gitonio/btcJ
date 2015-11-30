package btcJ;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import org.bitcoinj.core.*;
import org.bitcoinj.params.MainNetParams;

public class AddressScriptJ {

	public static void main(String[] args) {
		System.out.println("    ****************************************");
		System.out.println("    ***** WIF to Private key ***************");
		System.out.println("    ****************************************");

		System.out.println("1 - Take a Wallet Import Format string");
		String wif = "5JG9hT3beGTJuUAmCQEmNaxAuMacCTfXuw1R3FCXig23RQHMr4K";
		System.out.println("    " + wif);
		System.out.println("    " + DumpedPrivateKey.fromBase58(null, wif).getKey().getPrivateKeyAsHex());
		
		
		System.out.println("    ****************************************");
		System.out.println("    ***** Private Key to WIF ***************");
		System.out.println("    ****************************************");
		System.out.println("1 - Take a private key");
		
		String pk = "3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6";
		byte [] pkb = org.bitcoinj.core.Utils.parseAsHexOrBase58(pk);
        ECKey key = DumpedPrivateKey.fromBase58(MainNetParams.get(), wif).getKey();        
        System.out.println(key.getPrivateKeyAsWiF(MainNetParams.get()));
        
        
		System.out.println();
		System.out.println("    ****************************************");
		System.out.println("    ***** Private Key to Bitcoin Address ***");
		System.out.println("    ****************************************");
        System.out.println(key.toAddress(MainNetParams.get()));
        
        
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

}
