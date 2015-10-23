package btcJ;


import java.net.*;
import java.util.Calendar;
import java.io.*;

import org.apache.commons.codec.DecoderException;

public class MsgTest {

	public static void main(String[] args) {
		// 1) create a java calendar instance
		Calendar calendar = Calendar.getInstance();
		 
		// 2) get a java.util.Date from the calendar instance.
//		    this date will represent the current instant, or "now".
		java.util.Date now = calendar.getTime();
		System.out.println(now);
		
		byte[] ia = null;
		//byte[] sv = new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
		String sv = "010000000000000000000000000000000000ffff";
		int port = 8333;
		System.out.println(Integer.toHexString(port));
		// TODO Auto-generated method stub
        try {
        	ia = InetAddress.getByName("10.0.0.1").getAddress();
			//Socket client = new Socket("127.0.0.1", 1521);
        	for (int i = 0; i < ia.length; i++) {
				System.out.println(ia[i]);
			}
			System.out.println("iahex :"+Utils.toHex(ia));
			
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        
        
		try {
			byte[] bytes3;
			byte[] bytes4;
			bytes3 = org.apache.commons.codec.binary.Hex.decodeHex(Utils.toHex(ia).toCharArray());
			String ts = sv + Utils.toHex(ia) + Integer.toHexString(port);
			bytes4 = org.apache.commons.codec.binary.Hex.decodeHex(ts.toCharArray());
        	for (int i = 0; i < bytes4.length; i++) {
				System.out.println(bytes4[i]);
			}
        	System.out.println(Utils.toHex(bytes4));
		} catch (DecoderException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

        
        
	}

}
