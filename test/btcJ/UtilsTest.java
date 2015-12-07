package btcJ;

import static org.junit.Assert.*;

import java.io.IOException;

import org.apache.commons.codec.DecoderException;
import org.junit.Test;

public class UtilsTest {
	byte [] ba = new byte[10];
	int x = 0x42;
	@Test
	public void varint() throws IOException{
		ba = Utils.varint(0x42); //66
		byte [] eba = new byte []  {66};
		assertArrayEquals(eba,ba);
		ba = Utils.varint(0x123); //291
		eba = new byte [] {-3,35,1};
		assertArrayEquals(eba, ba);
		ba = Utils.varint(0x12345678); //305 419 896
		eba = new byte [] {-2,120,86,52,18};
		assertArrayEquals(eba, ba);
	}
	
	@Test
	public void varstr() throws IOException, DecoderException{
		byte [] eba = new byte [] {3,97,98,99};
		byte [] iba = new byte [] {97,98,99};
		byte [] oba = Utils.varstr(iba);
		assertArrayEquals(eba,oba);
		
		String str = "abc";
		byte [] strba =str.getBytes();
		oba = Utils.varstr(strba);
		assertArrayEquals(eba,oba);
		
		str = "3046022100e9044fae15d8ca64fb4f5397b4af15ebc843fbacfd4671bdb09762d19d1b2e67022100d04f170a405b908842e44267ca874bb1fa238b7c8c370db71561e82bb5f9876901";
		strba = org.apache.commons.codec.binary.Hex.decodeHex(str.toCharArray());
		oba = Utils.varstr(strba);
		System.out.println(Utils.toHex(oba));
		
	}
	
	@Test
	public void toHexB() throws DecoderException
	{
		byte [] sb =  "ab".getBytes();
		byte [] ba = Utils.toHexB(sb);
		byte [] eba = new byte [] {54,49,54,50};
		assertArrayEquals(eba,ba);
	}
}
