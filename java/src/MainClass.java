
import sun.security.rsa.RSAPrivateCrtKeyImpl;
import sun.security.rsa.RSAPrivateKeyImpl;
import sun.security.rsa.RSAPublicKeyImpl;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Random;

import javax.crypto.Cipher;

public class MainClass {

static final String HEXES = "0123456789ABCDEF";
    public static String getHex( byte [] raw ) {
        if ( raw == null ) {
            return null;
        }
        final StringBuilder hex = new StringBuilder( 2 * raw.length );
        for ( final byte b : raw ) {
            hex.append(HEXES.charAt((b & 0xF0) >> 4))
                    .append(HEXES.charAt((b & 0x0F)));
        }
        return hex.toString();
    }
    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        byte[] input = new byte[] { (byte) 0x31 };
        Cipher cipher = Cipher.getInstance("RSA/NONE/NoPadding", "BC");
//        Cipher cipher = Cipher.getInstance("RSA");
//        Cipher cipher = Cipher.getInstance("RSA");
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA", "BC");
        keygen.initialize(16);
        KeyPair keys = keygen.generateKeyPair();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        // BigInteger modulus = new BigInteger(512, new Random(0));
        BigInteger p = new BigInteger("61", 10);
        BigInteger q = new BigInteger("53", 10);
        BigInteger modulus = p.multiply(q);
        BigInteger e = new BigInteger("17", 10);
        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus, e);
        //new RSAPublicKeySpec(new BigInteger("12345678", 16), new BigInteger("11", 16));
        //RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);
//            new RSAPrivateKeySpec(new BigInteger(
//        "12345678", 16), new BigInteger("12345678",
//        16));

//        PublicKey pubKey = keys.getPublic();
//        PrivateKey privKey = keys.getPrivate();


//        BigInteger d = new BigInteger("2753", 10);
        BigInteger d = computeD(p, q, e);
        RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(modulus, d);

        PublicKey pubKey =  keyFactory.generatePublic(pubKeySpec);
        PrivateKey privKey = keyFactory.generatePrivate(privKeySpec);

//    PrivateKey privKey =
//            keyFactory.generatePrivate(new RSAPrivateCrtKeySpec(
//                    modulus,
//                    e,
//                    d,
//                    p,
//                    q,
//                    e,
//                    e,
//                    e
//                    ));

//        PublicKey pubKey = new RSAPublicKeyImpl(new BigInteger("12345678", 16), new BigInteger("11", 16));
//        PrivateKey privKey = new RSAPrivateKeyImpl();

        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        System.out.println("input: " + getHex(input));
        byte[] cipherText = cipher.doFinal(input);
        System.out.println("cipher: " + getHex(cipherText));

        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + getHex(plainText));
    }

    private static BigInteger computeD(BigInteger p, BigInteger q, BigInteger e) {
        BigInteger one = new BigInteger("1", 10);
        BigInteger minus_one = new BigInteger("-1", 10);
        BigInteger totient = p.subtract(one).multiply(q.subtract(one)) ;

        return e.modPow(minus_one, totient);

    }
}
