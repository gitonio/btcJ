package btcJ;

import static org.junit.Assert.*;

import org.junit.Test;

public class AddressTest {

	@Test
	public void wifToPrivateKey( ) {
		byte[] wif_enc = Address.wifToPrivateKey("5JG9hT3beGTJuUAmCQEmNaxAuMacCTfXuw1R3FCXig23RQHMr4K");
		assertTrue("Should be equal", Utils.toHex(wif_enc).toUpperCase().equals("3ABA4162C7251C891207B747840551A71939B0DE081F85C4E44CF7C13E41DAA6"));
	}
	
	@Test
	public void wifChecksum() {
		byte[] checksum = Address.wifChecksum("5JG9hT3beGTJuUAmCQEmNaxAuMacCTfXuw1R3FCXig23RQHMr4K");
		assertTrue("Should be equal", Utils.toHex(checksum).toUpperCase().equals("C609B824"));
	}
	
	@Test
	public void privateKeyToWif(){
		byte[] wif_enc = Address.privateKeyToWif("3ABA4162C7251C891207B747840551A71939B0DE081F85C4E44CF7C13E41DAA6", false);
		assertTrue("Should be equal", Base58.encode(wif_enc).equals("5JG9hT3beGTJuUAmCQEmNaxAuMacCTfXuw1R3FCXig23RQHMr4K"));
	}
	
	@Test
	public void privateKeyToPublicKey(){
		byte[] wif_enc = Address.privateKeyToPublicKey("3ABA4162C7251C891207B747840551A71939B0DE081F85C4E44CF7C13E41DAA6", false);
		assertTrue("Should be equal", Utils.toHex(wif_enc).equalsIgnoreCase("045c0de3b9c8ab18dd04e3511243ec2952002dbfadc864b9628910169d9b9b00ec243bcefdd4347074d44bd7356d6a53c495737dd96295e2a9374bf5f02ebfc176"));
	}
	
	@Test
	public void privateKeyToAddress(){
		byte[] wif_enc = Address.privateKeyToAddress("3ABA4162C7251C891207B747840551A71939B0DE081F85C4E44CF7C13E41DAA6", false, false);
		assertTrue("Should be equal", Base58.encode(wif_enc).equals("1thMirt546nngXqyPEz532S8fLwbozud8"));
	}
	
	@Test
	public void publicKeyToAddress(){
		byte[] wif_enc = Address.publicKeyToAddress("045c0de3b9c8ab18dd04e3511243ec2952002dbfadc864b9628910169d9b9b00ec243bcefdd4347074d44bd7356d6a53c495737dd96295e2a9374bf5f02ebfc176");
		System.out.println(Base58.encode(wif_enc));
		assertTrue("Should be equal", Base58.encode(wif_enc).equals("1thMirt546nngXqyPEz532S8fLwbozud8"));
	}
}
