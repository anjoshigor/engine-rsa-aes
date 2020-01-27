
package criptografia;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class GerenciadorAES {
     
     public SecretKey carregaChaveAES(byte[] secretKey) {

          return new SecretKeySpec(secretKey, 0, secretKey.length, "AES");
          
     }
     
     public byte[] criptografar(byte[] informacao, SecretKey secretKey) {
          
          try {
               
               Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
               byte[] iv = new byte[16];
               IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
               cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
               
               return cipher.doFinal(informacao);
               
          } catch (Exception e) {
               
               e.printStackTrace();
               
          }

          return null;
          
     }
     
     public byte[] decriptografar(byte[] informacaoCriptografada, SecretKey secretKey) {
          
          try {

               Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
               byte[] iv = new byte[16];
               IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
               cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
               
               
               return cipher.doFinal(informacaoCriptografada);
               
          } catch (Exception e) {
               
               e.printStackTrace();
               
          }

          return null;
          
     }

   

}
