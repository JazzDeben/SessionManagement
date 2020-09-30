/*
  - Data made available by nodes that have already executed are available in the sharedState variable.
  - The script should set outcome to either "true" or "false".
 */

import groovy.json.JsonSlurper;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Key;


class Crypto{
  
  private KeyStore keystore;
  private Key key;
  private String clearText;
  
  Crypto(String mypkcs12, String myalias, String mystorepass){
    this.keystore = this.getKeystore(mypkcs12, mystorepass);
    this.key = this.loadKey(this.keystore, mypkcs12, myalias, mystorepass);
  }
    
  public String encrypt_AES(String cleartext){
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.ENCRYPT_MODE, this.key);
    byte[] cryptoResult = cipher.doFinal(cleartext.getBytes());
    return Base64.encodeBase64String(cryptoResult);
  }

  public String decrypt_AES(String b64CryptoIn){
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.DECRYPT_MODE, this.key);
    byte[] cryptoResult = Base64.decodeBase64(b64CryptoIn.getBytes());
    byte[] decryptoResult = cipher.doFinal(cryptoResult);
    return new String(decryptoResult, StandardCharsets.UTF_8);
  }

  java.security.Key loadKey(KeyStore keystore, String mypkcs12, String myalias, String mystorepass){
    InputStream readStream = new FileInputStream(new File(mypkcs12));
    keystore.load(readStream, new String(mystorepass).toCharArray());
    java.security.Key key = keystore.getKey(new String(myalias), new String(mystorepass).toCharArray());
    return key;
  }

  java.security.KeyStore getKeystore(String mypkcs12, String mystorepass){
    java.security.KeyStore keystore = KeyStore.getInstance("pkcs12");
    keystore.load(new FileInputStream(new File(mypkcs12)), new String(mystorepass).toCharArray());
    return keystore;
  }

}

// get location of PKCS12 keystore
def mypkcs12 = java.lang.System.getenv("GROOVYPKCS12");
def myalias = java.lang.System.getenv("GROOVYPKCS12ALIAS");
def mystorepass = java.lang.System.getenv("GROOVYPKCS12PASS");

def password = transientState.get("password");
def clientResponse = null;

// if the password is NULL it is because the script is called from the custom node (password got lost)
// if the password is set, it is because the script is called from the previous CheckNumberOfSession script
// if password is set (not NULL) there was no other session to deal with therefore, the intension is always to login, so the clientResponse is set to "login"
// if the password is null, we check the intension of the end user to either login, or cancel.
if (password != null){
  clientResponse = "login";
} else {
  password = sharedState.get("password");
  def crypto = new Crypto(mypkcs12, myalias, mystorepass);
  password = crypto.decrypt_AES(password);
  clientResponse = sharedState.get("output");
}

if (clientResponse == "login"){
  transientState.put("password", password);
  outcome = "true";
} else {
  outcome = "false";
}
