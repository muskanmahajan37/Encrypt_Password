package com.java.encrypt;
import java.io.IOException;

import javax.crypto.*;
import javax.crypto.spec.*;
import sun.misc.*;

public class Encrypt
{
	private String characterEncoding;
	private Cipher encryptCipher;
    private BASE64Encoder base64Encoder = new BASE64Encoder();

    public Encrypt() {
    	
    }
    
    public Encrypt(byte[] keyBytes, byte[] ivBytes, String characterEncoding) throws Exception
    {
        SecretKey key = new SecretKeySpec(keyBytes, "DES");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        this.characterEncoding = characterEncoding;
        this.encryptCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        this.encryptCipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key, iv);
    }

    synchronized public String encrypt(String password) throws Exception
    {
        byte[] passwordBytes = password.getBytes(characterEncoding);
        byte[] encryptedPasswordBytes = this.encryptCipher.doFinal(passwordBytes);
        String encodedEncryptedPassword = this.base64Encoder.encode(encryptedPasswordBytes);
        return encodedEncryptedPassword;
    }

    public static void main(String[] args)
    {
    	String password = "modeler";
    	doEncrypt(password);
//    	String[] COMMAND = {
//                "cmd.exe", "/c", "start",
//                "<A HREF='mailto:ab33973@wellpoint.com' TITLE='Password Encrypted'>The Password you have supplied is encrypted.</A>"
//        };
//    	try {
//			Runtime.getRuntime().exec(COMMAND);
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
    }



	/**
	 * @param password
	 */
	public static String doEncrypt(String password) {

		String encodedEncryptedPassword = "";
		try
	        {
	            //Security.addProvider(new com.sun.crypto.provider.SunJCE());

	            final byte[] DESKeyBytes = {0x01, 0x02, 0x04, 0x08, 0x08, 0x04, 0x02, 0x01};

	            final byte[] ivBytes = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

	            Encrypt passwordEncryptAgent = new Encrypt(DESKeyBytes, ivBytes, "ASCII");

	            if(password!=null && password.length() > 0)
				{
					//System.out.println("Password : " + password);

					encodedEncryptedPassword = passwordEncryptAgent.encrypt(password);

					//System.out.println("Encrypted password : " + encodedEncryptedPassword);
				}
				else
				{
					System.out.println("\nERROR : Password must have atleast one character !!!");
				}
	        }
	        catch (Exception e)
	        {
	            e.printStackTrace(System.out);
	        }
	        return encodedEncryptedPassword;
	}
}
