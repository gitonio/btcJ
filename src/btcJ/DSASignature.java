package btcJ;

import java.io.IOException;
import java.math.BigInteger;

import org.apache.commons.codec.DecoderException;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DLSequence;


public class DSASignature 
{
    public static void decodeFromDER(byte[] bytes) {
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
            // OpenSSL deviates from the DER spec by interpreting these values as unsigned, though they should not be
            // Thus, we always use the positive versions. See: http://r6.ca/blog/20111119T211504Z.html
             
            System.out.println(Utils.toHex(r.getEncoded()));
            System.out.println(Utils.toHex(s.getEncoded()));
            byte[] x = new byte[r.getEncoded().length - 2];
            byte[] y = new byte[s.getEncoded().length - 3];
            
            
            System.arraycopy(r.getEncoded(), 2, x, 0, r.getEncoded().length - 2);
            System.out.println(Utils.toHex(x));
            System.arraycopy(s.getEncoded(), 3, y, 0, s.getEncoded().length - 3);
            System.out.println(Utils.toHex(y));
          
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            if (decoder != null)
                try { decoder.close(); } catch (IOException x) {}
        }
    }
    
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String derSig = "304502204c01fee2d724fb2e34930c658f585d49be2f6ac87c126506c0179e6977716093022100faad0afd3ae536cfe11f83afaba9a8914fc0e70d4c6d1495333b2fb3df6e8cae";
		byte [] privateKeyBytes = null;
		try {
			privateKeyBytes = org.apache.commons.codec.binary.Hex.decodeHex(derSig.toCharArray());
		} catch (DecoderException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		decodeFromDER(privateKeyBytes);
	}

} 
