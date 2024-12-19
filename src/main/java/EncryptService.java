import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

public class EncryptService {

    // AES
    private static final String KEY = "HOLAHOLAHOLAHOLA";
    private static final String ALGORITHM = "AES";
    private static final String ALGORITHM_FULL = "AES/CBC/PKCS5Padding";
    private static final String IV = "HOLAHOLAHOLAHOLA";


    public static String EncryptContentAES(String content) throws
            NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException,
            InvalidAlgorithmParameterException {

        IvParameterSpec ivSpec = new IvParameterSpec(IV.getBytes());
        SecretKeySpec key = new SecretKeySpec(KEY.getBytes(), ALGORITHM);

        Cipher cipher = Cipher.getInstance( ALGORITHM_FULL );
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encryptedBytes = cipher.doFinal( content.getBytes() );

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }




    public static String DecryptContentAES(String encryptedContent) throws
            NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException,
            InvalidAlgorithmParameterException {

        IvParameterSpec ivSpec = new IvParameterSpec(IV.getBytes());
        SecretKeySpec key = new SecretKeySpec(KEY.getBytes(), ALGORITHM);

        Cipher cipher = Cipher.getInstance(ALGORITHM_FULL);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedContent);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);

        return new String(decryptedBytes);
    }



    public static String EncryptContentRSA(String content) throws
            NoSuchAlgorithmException,
            InvalidKeySpecException,
            InvalidKeyException,
            NoSuchPaddingException,
            IllegalBlockSizeException,
            BadPaddingException {

        String moduleRAS = "91a7696ec59c9361df1480d3edeffcbfb6f71d88239e156ef0fcc5271d162a964dcded14c14d7684786e74b41d6c2f16442887e05c379b5bb9e4bdb50b6ccad5";
        String exponentRAS = "10001";


        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec publicKey = new RSAPublicKeySpec(
                new BigInteger(moduleRAS , 16) ,
                new BigInteger (exponentRAS , 16) );

        PublicKey pubKey = factory.generatePublic(publicKey);

        RSAPublicKey key = (RSAPublicKey) pubKey;

        Cipher cipher = Cipher.getInstance( "RSA" );
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal( content.getBytes() );

        return Base64.getEncoder().encodeToString(encryptedBytes);

    }

    public static String DecryptContentRSA(String encrypted) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        String modulo = "91a7696ec59c9361df1480d3edeffcbfb6f71d88239e156ef0fcc5271d162a964dcded14c14d7684786e74b41d6c2f16442887e05c379b5bb9e4bdb50b6ccad5";
        String exponente = "4a5130338bf2b32489ed6d3a353a712ce4cf3bab3df928187e2f8aecc5238d406ee3a193e1d94db905f21c2a963f80a95e66b5e127977ed0da0cf8b3af220161";


        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec privateKey = new RSAPrivateKeySpec( new BigInteger(modulo , 16) ,
                new BigInteger (exponente , 16) );

        PrivateKey privKey = factory.generatePrivate(privateKey);

        RSAPrivateKey key = (RSAPrivateKey) privKey;

        Cipher cipher = Cipher.getInstance( "RSA" );

        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] decodedBytes = Base64.getDecoder().decode(encrypted);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);

        return new String(decryptedBytes);

    }


}
