import java.security.PrivateKey;
import java.util.Base64;

import javax.crypto.SecretKey;

import criptografia.Configuracoes;
import criptografia.GerenciadorAES;
import criptografia.GerenciadorRSA;

public class App {

     public static void main(String[] args) {

          try {

               // Carregando Chave Privada 
               GerenciadorRSA engineRSA = new GerenciadorRSA();
               PrivateKey privateKey = engineRSA.carregaChavePrivada(Configuracoes.PRIVATE_KEY_EMISSOR);

               // Decodificando Base64 da chave AES
               byte[] secretKeyTemp = Base64.getDecoder().decode(Configuracoes.SECRET_KEY_EMISSOR);

               // Descriptografando chave AES 
               byte[] secretKeyByte = engineRSA.descriptografar(secretKeyTemp, privateKey);
               String aesBase64Key = Base64.getEncoder().encodeToString(secretKeyByte);
               System.out.println("Aes key: " + aesBase64Key);

               // Carrega chave AES
               GerenciadorAES engineEAS = new GerenciadorAES();
               SecretKey secretKey = engineEAS.carregaChaveAES(secretKeyByte);

               String bodyCriptografado = Configuracoes.MENSAGEM_CRIPTOGRAFADA;
               System.out.println("Encrypted message: " + bodyCriptografado);

               // ------------------------DE CRIPTOGRAFANDO CONTEÚDO------------------------
               byte[] dadosDecodeBase64 = Base64.getDecoder().decode(bodyCriptografado.getBytes());
               byte[] dadosDescriptografados = engineEAS.decriptografar(dadosDecodeBase64, secretKey);
               System.out.println("Decrypted message:" + new String(dadosDescriptografados, "UTF-8"));


          } catch (Exception e) {
               e.printStackTrace();
          }

     }

}