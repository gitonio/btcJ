package btcJ;

import static org.junit.Assert.*;

import org.junit.Test;

public class Base58CheckTest {

	@Test
	public void Base58CheckDecode() {
		byte [] op = Base58Check.decode("869JBzBrmo8");
		System.out.println("Decode: " + Utils.toHex(op));
		assertEquals("2a616263", Utils.toHex(op));
	}
	
	@Test
	public void Base58CheckEncode() {
		byte[] ba = new byte[] {97,98,99};
		String op = Base58Check.encode((byte) 42, ba, false);
		assertEquals("869JBzBrmo8",op);
		System.out.println("Encode: " + op);
	}


}
