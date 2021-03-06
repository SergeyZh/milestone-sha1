
import sun.security.rsa.RSAPrivateCrtKeyImpl;
import sun.security.rsa.RSAPrivateKeyImpl;
import sun.security.rsa.RSAPublicKeyImpl;
import sun.security.util.BigInt;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Random;

import javax.crypto.Cipher;

// Modulus=E17F7E822384B578E1C8DF3841B6EF1DDC05F821D4A8AB42C932680CBFB9955A2FCBE7A74CA09515D585164A3A3B7F5C0F47D417810C542B8E556765B7991024F05832A1D56D5F3AE77FD3E628FE24D0B2296C52099D3BD5741A33645483961EC697B34A39FCDFB515C849BB6E7835A75F8965FA4FBD6105B4F0B9F9D786C9DADF7E0E8CC07AD3C1FD243B43C21091B8ECB58320AB855D7FC85598FD9A63A1DE0B618F7C45296D9CBDA7A6FB242B0DCAB1CF4ED103077EFBE5AA9484989E32FF256D935DCFD981FB2C2F2AF24DE2E825D2CACD6586333E369FBAE1898ADA7A3C360B1FDE19CC172FB6A1E557C48F8D214B966DA68B21CA6EC96ADDEE796B0F69
// 28466488337384072326773684055768915601344425573767052799975129172482592144418213724723920044104190633134239937643675659236066551945034657978083446368474774318217378185332316721177395798230734789277393544897322333580556309890909102320972853963432714735260787943840734652242508499880406093441841952168601920932698716344590558231724302308471292688360074705446869940789110975418409108199035187427094107736153860772629793514926936882564182490286262959136708919086238919101069935461080528108869029455684022249451450196046089441562214393836747760074657488698367432264087612849401048061373807593458393890332404178627307704169
// SquareRoot: f043f5952874a33de6ce581e4d28c3f1e4a26adf45c39895b64b894f6dd01dba4bd2f65f9111bf999853af2b7d14fae201d19dc2d6ee6f2f8c6d20eba2d69280b2b66e9e7388bd3a920e58ee04cf4fc3d7b4a4493de78bd34022af48f83959b458956e9260e72f54bbe578a807ca0fa64f136f91134fd1a4608cf3ae70730d85



public class MainClass {
    static String prime_str="00c9fca669aea268cb299a4c609ae8e81c3c61741632d25351ef3481d4c518ba30384af26f6888bf68da814013cd8d76d3729b16a4bd949c78298cb54139e5ed316310dbd51a3ced430c99d7a16a4a11d01f4b563f647fb660099413480c45d2d59f8cacdc98978be2823ac976820b2d9c69ac2473653299b6d8f963e40a9f72bd";

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


        BigInteger milestone_pub = new BigInteger("E17F7E822384B578E1C8DF3841B6EF1DDC05F821D4A8AB42C932680CBFB9955A2FCBE7A74CA09515D585164A3A3B7F5C0F47D417810C542B8E556765B7991024F05832A1D56D5F3AE77FD3E628FE24D0B2296C52099D3BD5741A33645483961EC697B34A39FCDFB515C849BB6E7835A75F8965FA4FBD6105B4F0B9F9D786C9DADF7E0E8CC07AD3C1FD243B43C21091B8ECB58320AB855D7FC85598FD9A63A1DE0B618F7C45296D9CBDA7A6FB242B0DCAB1CF4ED103077EFBE5AA9484989E32FF256D935DCFD981FB2C2F2AF24DE2E825D2CACD6586333E369FBAE1898ADA7A3C360B1FDE19CC172FB6A1E557C48F8D214B966DA68B21CA6EC96ADDEE796B0F69", 16);
        BigDecimal test = new BigDecimal(milestone_pub);
        BigSquareRoot root = new BigSquareRoot();
        BigDecimal res = root.get(milestone_pub);

        System.out.println(res.toBigInteger().toString(16));


        //BigInteger sqrt = milestone_pub.
        //BigDecimal dec = new BigDecimal(milestone_pub);
        BigInteger divider = new BigInteger(prime_str, 16);
        BigInteger two = new BigInteger("2");
        BigInteger minReminder = divider.max(BigInteger.ONE);
        while (true) {
            //System.out.println(milestone_pub.toString(10));
            BigInteger[] x = milestone_pub.divideAndRemainder(divider);
            BigInteger reminder = x[1];
            BigInteger first = x[0];
            if (reminder.compareTo(minReminder) == -1) {
                minReminder = reminder;
                System.out.println(reminder.toString(10)+", "+  first.toString(10));
            }
            divider = divider.nextProbablePrime();
        }
/*
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
*/
    }

    private static BigInteger computeD(BigInteger p, BigInteger q, BigInteger e) {
        BigInteger one = new BigInteger("1", 10);
        BigInteger minus_one = new BigInteger("-1", 10);
        BigInteger totient = p.subtract(one).multiply(q.subtract(one)) ;

        return e.modPow(minus_one, totient);

    }
}
