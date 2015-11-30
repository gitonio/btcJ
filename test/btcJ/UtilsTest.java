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
	public void varstr() throws IOException{
		byte [] eba = new byte [] {3,97,98,99};
		byte [] iba = new byte [] {97,98,99};
		byte [] oba = Utils.varstr(iba);
		assertArrayEquals(eba,oba);
		
		String str = "abc";
		byte [] strba =str.getBytes();
		oba = Utils.varstr(strba);
		assertArrayEquals(eba,oba);
		
		
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
