package btcJ;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Random;
import java.util.TimeZone;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.lang3.ArrayUtils;

public class Message {
	public static byte[] getVersion(){
		/*	    version = 60002
	    	    services = 1
	    	    timestamp = int(time.time())
	    	    print(time.time())
	    	    print(timestamp)
	    	    #addr_me = utils.netaddr(socket.inet_aton("127.0.0.1"), 8333)
	    	    #addr_you = utils.netaddr(socket.inet_aton("127.0.0.1"), 8333)
	    	    print(socket.inet_aton("127.0.0.1"))
	    	    addr_me = utils.netaddr(socket.inet_aton("127.0.0.1"), 19000)
	    	    print('addr_me', addr_me)
	    	    addr_you = utils.netaddr(socket.inet_aton("127.0.0.1"), 19001)
	    	    nonce = random.getrandbits(64)
	    	    print(nonce)
	    	    sub_version_num = utils.varstr(b'')
	    	    start_height = 0

	    	    payload = struct.pack('<LQQ26s26sQsL', version, services, timestamp, addr_me,
	    	        addr_you, nonce, sub_version_num, start_height)
	    	    return makeMessage(magic, 'version', payload)
		 */		
		String sv = "010000000000000000000000000000000000ffff";
		int version = 60002;
		long timestamp = System.currentTimeMillis() / 1000l ;
		byte[] recipient = null;
		byte[] sender = null;
		int port = 8333;

		try {
			recipient = 	InetAddress.getByName("10.0.0.1").getAddress();
			sender = 		InetAddress.getByName("10.0.0.1").getAddress();

			//Socket client = new Socket("127.0.0.1", 1521);

		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		Random rand = new Random();
		System.out.println(Integer.toHexString(version));
		Utils.toHex(recipient);
		Integer.toHexString(19000);
		Utils.toHex(sender);
		Integer.toHexString(19001);
		Long.toHexString(rand.nextLong());
		Integer.toHexString(version);
		System.out.println(Long.toHexString(timestamp));
		Integer.toHexString(8333);
		
		
		byte[] versionb = new byte[4];
		byte[] timestampb = new byte[8];
		byte[] recipientb = new byte[26];
		byte[] senderb = new byte[26];
		byte[] tempb = null;
		try {
			tempb = org.apache.commons.codec.binary.Hex.decodeHex(Integer.toHexString(version).toCharArray());
			System.arraycopy(tempb, 0, versionb, tempb.length, tempb.length);
			tempb = org.apache.commons.codec.binary.Hex.decodeHex(Long.toHexString(timestamp).toCharArray());
			System.arraycopy(tempb, 0, timestampb, 0, tempb.length);
			
			tempb = org.apache.commons.codec.binary.Hex.decodeHex(sv.toCharArray());
			System.arraycopy(tempb, 0, recipientb, 0, tempb.length);
			
			System.arraycopy(recipient, 0, recipientb, tempb.length, recipient.length);
			
			tempb = org.apache.commons.codec.binary.Hex.decodeHex(Integer.toHexString(port).toCharArray());
			System.arraycopy(tempb, 0, recipientb, 24, tempb.length);
			
			tempb = org.apache.commons.codec.binary.Hex.decodeHex(sv.toCharArray());
			System.arraycopy(tempb, 0, senderb, 0, tempb.length);
			
			System.arraycopy(sender, 0, senderb, tempb.length, recipient.length);
			
			tempb = org.apache.commons.codec.binary.Hex.decodeHex(Integer.toHexString(port).toCharArray());
			System.arraycopy(tempb, 0, senderb, 24, tempb.length);
			
		} catch (DecoderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		byte[] servicesb = new byte[] { 0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
		
		

		ArrayUtils.reverse(versionb);		
		System.out.println("version: " + Utils.toHex(versionb));
		System.out.println("services: " + Utils.toHex(servicesb));
		System.out.println("timestamp:" + Utils.toHex(timestampb));
		System.out.println("recipient:" + Utils.toHex(recipientb));
		System.out.println("sender:" + Utils.toHex(senderb));
		return null;

	}
}
