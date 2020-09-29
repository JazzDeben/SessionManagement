/*
  - Data made available by nodes that have already executed are available in the sharedState variable.
  - The script should set outcome to either "true" or "false".
 */

import org.forgerock.util.promise.PromiseImpl
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import java.lang.System;

import org.forgerock.json.JsonValue;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.object;

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
// collect user login information for the next node
String username = sharedState.get("username");
String password = transientState.get("password");

// get amadmin credentials

def amadmin = java.lang.System.getenv("AMADMIN");
def ampassword = java.lang.System.getenv("AMPASSWORD");

// get location of PKCS12 keystore

def mypkcs12 = java.lang.System.getenv("GROOVYPKCS12");
def myalias = java.lang.System.getenv("GROOVYPKCS12ALIAS");
def mystorepass = java.lang.System.getenv("GROOVYPKCS12PASS");

// get URL of AM

def myAM65 = java.lang.System.getenv("AMURL");
def myRealm = java.lang.System.getenv("AMREALM");

// Start getting number of sessions
// obtain an SSO token to query the APIs
Request request = new Request();
request.setMethod("POST");
request.setUri(myAM65+"/json/authenticate");
request.getHeaders().add("Content-Type", "application/json");
request.getHeaders().add("X-OpenAM-Username", amadmin);
request.getHeaders().add("X-OpenAM-Password", ampassword);
request.getHeaders().add("Accept-API-Version", "resource=2.0,protocol=1.0");

def response = httpClient.send(request).get();
def jsonToken = null;
def jsonSlurper = new JsonSlurper();
  
if(response != null){
  jsonToken = jsonSlurper.parseText((String) response.getEntity());
} else {
  logger.error("RESPONSE STATUS: NULL");
}

// with the SSO token we can request the number of active session for this user

request = new org.forgerock.http.protocol.Request();
request.setMethod("GET");
request.setUri(myAM65+"/json/sessions?_queryFilter=username%20eq%20%22"+username+"%22%20and%20realm%20eq%20%22%2F"+myRealm+"%22");
request.getHeaders().add("Content-Type", "application/json");
request.getHeaders().add("Accept-API-Version", "resource=3.1");
request.getHeaders().add("Cookie", "iPlanetDirectoryPro="+jsonToken.tokenId);

def jsonSessions = null;
def newSession = null;
def clientResponse = null;

response = httpClient.send(request).get();


// the number of session is revealed here. 
// If the number is higher or equal to 1 there will be a dialogue popup
// To get the popup the outcome of this node is false which will be used
// to drive the interaction in the next node
if(response != null)
{
  jsonSessions = jsonSlurper.parseText((String) response.getEntity());
  if (jsonSessions.resultCount >= 1) {
    clientResponse = "false";
  } else {
    clientResponse = "true";
  }
} else {
  clientResponse = "true";
}

// put the password in the transient state for the next script
transientState.put("password", password);

//encrypt the password in case it goes to the custom node (where the transient password is lost)
def crypto = new Crypto(mypkcs12, myalias, mystorepass);

password = crypto.encrypt_AES(password);

// save the encrypted password in the shared state
sharedState.put("password", password);

// if outcome is true then the next node is a password challenge
// if outcome is false then the next node will display a popup message about existing sessions
outcome = clientResponse;
