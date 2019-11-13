package iit.ece443.prj01;

import java.security.MessageDigest;
import java.util.Arrays;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.AEADBadTagException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;


import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;


public class Main
{
    public static void main(String[] args)
        throws Exception
    {
	AES256();
	System.out.println();
	AES512();
	System.out.println();
	verifyMD5();
	System.out.println();

	perfMD5();
	System.out.println();
	perf256();
	System.out.println();
	perf512();
	System.out.println();

	verifyAESGCM();
	System.out.println();
	System.out.println("\n Modified for Attack: ");
	String msg = "Hello world!";
	attackAESGCM(msg);
	System.out.println();
	verifyAESCBC(); // bonus question
	System.out.println();
    perfAESGCM();
	System.out.println();
	perfAESCBC();  // bonus question
    }

    private static void AES256()
        throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("sha-256");

        String str = "Hello world!";

        md.update(str.getBytes("UTF-8"));
        byte[] hash = md.digest();

        System.out.printf("AES256 of [%s]%n", str);
        System.out.printf("Computed: %s%n", hexString(hash));
    }
    private static void AES512()
        throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("sha-512");

        String str = "Hello world!";

        md.update(str.getBytes("UTF-8"));
        byte[] hash = md.digest();

        System.out.printf("AES512 of [%s]%n", str);
        System.out.printf("Computed: %s%n", hexString(hash));
    }

    private static String hexString(byte[] buf)
    {
        StringBuilder sb = new StringBuilder();
        for (byte b: buf)
            sb.append(String.format("%02X", b));
        return sb.toString();
    }

    private static void verifyMD5()
        throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("MD5");

        String str = "Hello world!";
        String md5 = "86FB269D190D2C85F6E0468CECA42A20";

        md.update(str.getBytes("UTF-8"));
        byte[] hash = md.digest();

        System.out.printf("MD5 of [%s]%n", str);
        System.out.printf("Computed: %s%n", hexString(hash));
        System.out.printf("Expected: %s%n", md5);
    }

    private static void perfMD5()
        throws Exception
    {
        int MB = 256;

        byte[] buf = new byte[MB*1024*1024];
        Arrays.fill(buf, (byte)0);

        MessageDigest md = MessageDigest.getInstance("MD5");

        long start = System.currentTimeMillis();
        md.update(buf);
        byte[] hash = md.digest();
        long stop = System.currentTimeMillis();

        System.out.printf("MD5 of %dMB 0x00%n", MB);
        System.out.printf("Computed: %s%n", hexString(hash));
        System.out.printf("Time used: %d ms%n", stop-start);
        System.out.printf("Performance: %.2f MB/s%n", MB*1000.0/(stop-start));
    }

	private static void perf256()
        throws Exception
    {
        int MB = 256;

        byte[] buf = new byte[MB*1024*1024];
        Arrays.fill(buf, (byte)0);

        MessageDigest md = MessageDigest.getInstance("SHA-256");

        long start = System.currentTimeMillis();
        md.update(buf);
        byte[] hash = md.digest();
        long stop = System.currentTimeMillis();

        System.out.printf("SHA-256 of %dMB 0x00%n", MB);
        System.out.printf("Computed: %s%n", hexString(hash));

        System.out.printf("Time used: %d ms%n", stop-start);
        System.out.printf("Performance: %.2f MB/s%n", MB*1000.0/(stop-start));
    }
	private static void perf512()
        throws Exception
    {
        int MB = 256;

        byte[] buf = new byte[MB*1024*1024];
        Arrays.fill(buf, (byte)0);

        MessageDigest md = MessageDigest.getInstance("SHA-512");

        long start = System.currentTimeMillis();
        md.update(buf);
        byte[] hash = md.digest();
        long stop = System.currentTimeMillis();

        System.out.printf("SHA-512 of %dMB 0x00%n", MB);
        System.out.printf("Computed: %s%n", hexString(hash));

        System.out.printf("Time used: %d ms%n", stop-start);
        System.out.printf("Performance: %.2f MB/s%n", MB*1000.0/(stop-start));
    }


    private static void verifyAESGCM()
        throws Exception
    {
        String msg = "Hello world!";
        byte[] buf = new byte[1000];

        byte[] iv = new byte[12];
        Arrays.fill(iv, (byte)0);
        GCMParameterSpec ivSpec = new GCMParameterSpec(128, iv);

        byte[] key = new byte[16];
        Arrays.fill(key, (byte)1);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        byte[] plaintext = msg.getBytes("UTF-8");

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        int len = cipher.update(plaintext, 0, plaintext.length, buf);
        len += cipher.doFinal(buf, len);

        byte[] ciphertext = Arrays.copyOf(buf, len-16);
        byte[] mac = Arrays.copyOfRange(buf, len-16, len);

        System.out.printf("AES/GCM of [%s]%n", msg);
        System.out.printf("Plaintext:  %s%n", hexString(plaintext));
        System.out.printf("Ciphertext: %s%n", hexString(ciphertext));
        System.out.printf("MAC:        %s%n", hexString(mac));

        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        int len2 = cipher.update(ciphertext, 0, ciphertext.length, buf);
        len2 += cipher.update(mac, 0, mac.length, buf, len2);
        len2 += cipher.doFinal(buf, len2);

        byte[] plaintext2 = Arrays.copyOf(buf, len2);
        System.out.printf("Decrypted:  %s%n", hexString(plaintext2));
    }

private static void attackAESGCM(String msg) throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException
 {
	 byte[] buf = new byte[1000];

     byte[] iv = new byte[12];
     Arrays.fill(iv, (byte)0);
     GCMParameterSpec ivSpec = new GCMParameterSpec(128, iv);

     byte[] key = new byte[16];
     Arrays.fill(key, (byte)1);
     SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

     Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

     byte[] plaintext = msg.getBytes("UTF-8");

     cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
     int len = cipher.update(plaintext, 0, plaintext.length, buf);
     len += cipher.doFinal(buf, len);

     byte[] ciphertext = Arrays.copyOf(buf, len-16);
     byte[] mac = Arrays.copyOfRange(buf, len-16, len);

     System.out.printf("AES/GCM of [%s]%n", msg);
     System.out.printf("Plaintext:  %s%n", hexString(plaintext));
     System.out.printf("Ciphertext: %s%n", hexString(ciphertext));
     System.out.printf("MAC:        %s%n", hexString(mac));

     try{
		 String msgNew = "Cyber Attack happens";
		ciphertext = msgNew.getBytes("UTF-8");
		cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
		int len2 = cipher.update(ciphertext, 0, ciphertext.length, buf);
        	len2 += cipher.update(mac, 0, mac.length, buf, len2);
        	len2 += cipher.doFinal(buf, len2);
        	byte[] plaintext2 = Arrays.copyOf(buf, len2);
        	System.out.printf("Decrypted:  %s%n", hexString(plaintext2));

     }catch(AEADBadTagException e) {

    	 System.out.println("\n The ciphertext was attacked ");

     }

	}


    private static void verifyAESCBC()
        throws Exception
    {
        String msg = "Hello world!";
        byte[] buf = new byte[1000];

        byte[] iv = new byte[16];
        Arrays.fill(iv, (byte)0);
        IvParameterSpec IvParameterSpec = new IvParameterSpec(iv);

        byte[] key = new byte[16];
        Arrays.fill(key, (byte)1);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        byte[] plaintext = msg.getBytes("UTF-8");

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, IvParameterSpec);
        int len = cipher.update(plaintext, 0, plaintext.length, buf);
        len += cipher.doFinal(buf, len);

        byte[] ciphertext = Arrays.copyOf(buf, len);

        System.out.printf("AES/CBC of [%s]%n", msg);
        System.out.printf("Plaintext:  %s%n", hexString(plaintext));
        System.out.printf("Ciphertext: %s%n", hexString(ciphertext));

        cipher.init(Cipher.DECRYPT_MODE, keySpec, IvParameterSpec);
        int len2 = cipher.update(ciphertext, 0, ciphertext.length, buf);
        len2 += cipher.doFinal(buf, len2);

        byte[] plaintext2 = Arrays.copyOf(buf, len2);
        System.out.printf("Decrypted:  %s%n", hexString(plaintext2));
    }



    private static void perfAESGCM()
        throws Exception
    {
        int MB = 64;

        byte[] plaintext = new byte[MB*1024*1024];
        Arrays.fill(plaintext, (byte)0);

        byte[] buf = new byte[MB*1024*1024+16];

        byte[] iv = new byte[12];
        Arrays.fill(iv, (byte)0);
        GCMParameterSpec ivSpec = new GCMParameterSpec(128, iv);

        byte[] key = new byte[16];
        Arrays.fill(key, (byte)1);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        long startE = System.currentTimeMillis();
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        int len = cipher.update(plaintext, 0, plaintext.length, buf);
        len += cipher.doFinal(buf, len);
        long stopE = System.currentTimeMillis();

        byte[] ciphertext = Arrays.copyOf(buf, len-16);
        byte[] mac = Arrays.copyOfRange(buf, len-16, len);

        System.out.printf("AES/GCM of %dMB 0x00%n", MB);
        System.out.printf("Plaintext:  %s[MD5]%n",
            hexString(MessageDigest.getInstance("MD5").digest(plaintext)));
        System.out.printf("MAC:        %s%n", hexString(mac));

        long startD = System.currentTimeMillis();
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        int len2 = cipher.update(ciphertext, 0, ciphertext.length, buf);
        len2 += cipher.update(mac, 0, mac.length, buf, len2);
        len2 += cipher.doFinal(buf, len2);
        long stopD = System.currentTimeMillis();

        byte[] plaintext2 = Arrays.copyOf(buf, len2);
        System.out.printf("Decrypted:  %s[MD5]%n",
            hexString(MessageDigest.getInstance("MD5").digest(plaintext2)));

        System.out.printf(
            "Time used: encryption %d ms, decryption %d ms%n",
            stopE-startE, stopD-startD);
        System.out.printf(
            "Performance: encryption %.2f MB/s, decryption %.2f MB/s%n",
            MB*1000.0/(stopE-startE), MB*1000.0/(stopD-startD));
    }
private static void perfAESCBC()
        throws Exception
    {
        int MB = 64;

        byte[] plaintext = new byte[MB*1024*1024];
        Arrays.fill(plaintext, (byte)0);

        byte[] buf = new byte[MB*1024*1024+16];

        byte[] iv = new byte[16];
        Arrays.fill(iv, (byte)0);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        byte[] key = new byte[16];
        Arrays.fill(key, (byte)1);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");

        long startE = System.currentTimeMillis();
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        int len = cipher.update(plaintext, 0, plaintext.length, buf);
        len += cipher.doFinal(buf, len);
        long stopE = System.currentTimeMillis();

        byte[] ciphertext = Arrays.copyOf(buf, len-16);
        byte[] mac = Arrays.copyOfRange(buf, len-16, len);

        System.out.printf("AES/CBC of %dMB 0x00%n", MB);
        System.out.printf("Plaintext:  %s[MD5]%n",
            hexString(MessageDigest.getInstance("MD5").digest(plaintext)));
        System.out.printf("MAC:        %s%n", hexString(mac));

        long startD = System.currentTimeMillis();
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        int len2 = cipher.update(ciphertext, 0, ciphertext.length, buf);
        len2 += cipher.update(mac, 0, mac.length, buf, len2);
        len2 += cipher.doFinal(buf, len2);
        long stopD = System.currentTimeMillis();

        byte[] plaintext2 = Arrays.copyOf(buf, len2);
        System.out.printf("Decrypted:  %s[MD5]%n",
            hexString(MessageDigest.getInstance("MD5").digest(plaintext2)));

        System.out.printf(
            "Time used: encryption %d ms, decryption %d ms%n",
            stopE-startE, stopD-startD);
        System.out.printf(
            "Performance: encryption %.2f MB/s, decryption %.2f MB/s%n",
            MB*1000.0/(stopE-startE), MB*1000.0/(stopD-startD));
    }

}
