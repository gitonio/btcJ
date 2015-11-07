package btcJ;
import static org.junit.Assert.*;

import org.junit.Test;


public class MessageTest {

	@Test
	public void getVersion() {
		byte[] wif_enc = Message.getVersion();
		System.out.println("MessageTest");
	}

}
