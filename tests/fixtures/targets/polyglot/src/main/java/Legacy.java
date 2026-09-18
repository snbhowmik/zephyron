import java.security.MessageDigest;
import javax.crypto.Cipher;

public class Legacy {
    public byte[] run(byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }
}
