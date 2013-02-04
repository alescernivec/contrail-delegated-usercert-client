/*
 * Copyright 2012 Contrail Consortium.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.contrail.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import org.junit.*;

import java.io.IOException;
import java.security.Security;
import java.util.Calendar;
import java.util.Date;
import java.util.Properties;


import org.apache.http.HttpException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import static org.junit.Assert.*;

/**
 *
 * @author ianjohnson
 */
public class DelegatedUserCertClientTest {

  private static SecurityCommons sc = new SecurityCommons();

  @Test
  public void dummyTest() {
    System.out.println("dummy");
  }

  @BeforeClass
  public static void setUpClass() throws Exception {

    Security.addProvider(new BouncyCastleProvider());

  }
//  @Test

  public void testFOpenP12()
    throws Exception {

    System.out.println("openP12");

    String propsPath = "./src/test/resources/keystore.p12";

    File propsFile = null;

    try {

      propsFile = new File(propsPath);
      if (!propsFile.exists()) {
        throw new FileNotFoundException(propsPath);
      }

    } catch (FileNotFoundException ex) {
      System.err.println(ex);
    }

  }

  @Test
  public void testGetDelegatedUserCert()
    throws Exception {

    System.out.println("getDelegatedUserCert w/o server pass");


    /*
     * If the propsFile property isn't set, read the properties files from a hard-wired locationn
     * 
     */

    String propsFile = System.getProperty("propsFile",
      "./src/test/resources/ucstest.properties");

    Properties props = null;

    try {

      props = new Properties();
      props.load(new FileInputStream(propsFile));

    } catch (Exception ex) {
      System.err.println(ex);
    }

//    System.setProperty("javax.net.debug", "ssl");

    /*
     * If the targetUrl property isn't set, use a hard-wired URL
     * 
     */
    //String uriSpec = "https://one-test.contrail.rl.ac.uk:8443/ca/delegateduser";
    String uriSpec = "https://contrail.federation.ca:8445/ca/delegateduser";

    KeyPair keyPair = sc.generateKeyPair("RSA", 2048);

    String signatureAlgorithm = "SHA256withRSA";

    /*
     * Use a well-known username/password combination
     * 
     */

    System.setProperty("javax.net.debug", "ssl");


    String proxyHost = null;
    String proxyPortSpec = null;
    String proxyScheme = null;
    DelegatedCertClient instance =
      new DelegatedCertClient(uriSpec, true,
    	      "contrail-federation-web-key-store.pkcs12", "contrail",    		  
    	      "egi-cloud-ca-keystore.jks", "contrail"        
    );
    
    X509Certificate result = null;

    String userID = "1";

    try {
      System.out.printf("Calling %s.%n", uriSpec);

      result = instance.getCert(keyPair, signatureAlgorithm, userID, true);

      if (result == null) {

        throw new Exception(); // Throw an Exception to signal test has failed

      }


      System.out.println("Delegated User Private Key:");
      sc.writeKey(System.out, keyPair.getPrivate());

      System.out.println("\nDelegated User Certificate from CA Server:");

      sc.writeCertificate(System.out, result);

    } catch (IllegalArgumentException ex) {

      System.err.printf(ex.getLocalizedMessage());

    }

  }

  /*
   * Method for integration test against an external server
   * 
   */
//  @Test
  public void testGetDelegatedUserCertWithStorePass()
    throws Exception {

    System.out.println("getDelegatedUserCert WITH server pass");


    /*
     * If the propsFile property isn't set, read the properties files from a hard-wired locationn
     * 
     */

    String propsFile = System.getProperty("propsFile",
      "./src/test/resources/ucstest.properties");

    Properties props = null;

    try {

      props = new Properties();
      props.load(new FileInputStream(propsFile));

    } catch (Exception ex) {
      System.err.println(ex);
    }

//    System.setProperty("javax.net.debug", "ssl");

    /*
     * If the targetUrl property isn't set, use a hard-wired URL
     * 
     */
    String uriSpec = "https://one-test.contrail.rl.ac.uk:8443/ca/delegateduser";

    KeyPair keyPair = sc.generateKeyPair("RSA", 2048);

    String signatureAlgorithm = "SHA256withRSA";

    /*
     * Use a well-known username/password combination
     * 
     */

//    System.setProperty("javax.net.debug", "ssl");


    String proxyHost = null;
    String proxyPortSpec = null;
    String proxyScheme = null;
    DelegatedCertClient instance =
      new DelegatedCertClient(uriSpec, true,
      "./src/test/resources/cloud052.gridpp.rl.ac.uk-keystore.p12" /* lcg0710.gridpp.rl.ac.uk-keystore.p12" */, "client",
      //      "/Library/Java/Home/lib/security/cacerts", "changeit");

      "./src/test/resources/caserver.jks", "caserver");

    /* Can use either the CA certs file, or a truststore containing the actual server SSL cert */
    /* Should test using a TERENA CA cert on its own? */



    X509Certificate result = null;

    String userID = "3";

    try {
      System.out.printf("Calling %s.%n", uriSpec);

      result = instance.getCert(keyPair, signatureAlgorithm, userID, true);

      if (result == null) {

        throw new Exception(); // Throw an Exception to signal test has failed

      }


      System.out.println("Delegated User Private Key:");
      sc.writeKey(System.out, keyPair.getPrivate());

      System.out.println("\nDelegated User Certificate from CA Server:");

      sc.writeCertificate(System.out, result);

    } catch (IllegalArgumentException ex) {

      System.err.printf(ex.getLocalizedMessage());

    }

  }

// @Test
  public void testGetCertInvalidTruststore()
    throws Exception {

    System.out.println("%ngetCertInvalidTruststore");


    /*
     * If the propsFile property isn't set, read the properties files from a hard-wired locationn
     * 
     */

    String propsFile = System.getProperty("propsFile",
      "./src/test/resources/ucstest.properties");

    Properties props = null;

    try {

      props = new Properties();
      props.load(new FileInputStream(propsFile));

    } catch (Exception ex) {
      System.err.println(ex);
    }

    /*
     * If the targetUrl property isn't set, use a hard-wired URL
     * 
     */
    String uriSpec = "https://one-test.contrail.rl.ac.uk:8443/ca/delegateduser";

    KeyPair keyPair = sc.generateKeyPair("RSA", 2048);

    String signatureAlgorithm = "SHA256withRSA";


    String proxyHost = null;
    String proxyPortSpec = null;
    String proxyScheme = null;
    DelegatedHostCertClient instance =
      new DelegatedHostCertClient(uriSpec, true,
      "./src/test/resources/keystore.p12", "client",
      "./src/test/resources/ca-signing-cert.jks", "caserver");

    X509Certificate result = null;

    String userID = "1";

    try {
      System.out.printf("Invalid - Calling %s.%n", uriSpec);

      result = instance.getCert(keyPair, signatureAlgorithm, userID, true);
      fail("Should not complete SSL handshakre");

      if (result == null) {

        throw new Exception(); // Throw an Exception to signal test has failed

      }

      System.err.println("(Delegeated) User Private Key:");
      sc.writeKey(System.out, keyPair.getPrivate());

      System.out.println("(Delegeated) User Certificate from CA Server:");

      sc.writeCertificate(System.out, result);

    } catch (javax.net.ssl.SSLPeerUnverifiedException ex) {
      System.err.append("Caught SSLPeerUnverifiedException as expected");
      System.err.printf(ex.getLocalizedMessage());

    } catch (Exception ex) {
      System.err.printf(ex.getLocalizedMessage());
      System.err.println("%n");
    }

  }

  public void testGetHostCert()
    throws Exception {

    System.out.println("getCert");


    /*
     * If the propsFile property isn't set, read the properties files from a hard-wired locationn
     * 
     */

    String propsFile = System.getProperty("propsFile",
      "./src/test/resources/ucstest.properties");

    Properties props = null;

    try {

      props = new Properties();
      props.load(new FileInputStream(propsFile));

    } catch (Exception ex) {
      System.err.println(ex);
    }

    /*
     * If the targetUrl property isn't set, use a hard-wired URL
     * 
     */
    String uriSpec = "https://one-test.contrail.rl.ac.uk:8443/ca/host";

    KeyPair keyPair = sc.generateKeyPair("RSA", 2048);

    String signatureAlgorithm = "SHA256withRSA";

    /*
     * Use a well-known username/password combination
     * 
     */



    String proxyHost = null;
    String proxyPortSpec = null;
    String proxyScheme = null;
    DelegatedHostCertClient instance =
      new DelegatedHostCertClient(uriSpec, true,
      "./src/test/resources/keystore.p12", "client",
      "./src/test/resources/caserver.jks", "caserver");

    X509Certificate result = null;

    String userID = "contrail-client.contrail.rl.ac.uk";

    try {
      System.out.printf("Calling %s.%n", uriSpec);

      result = instance.getCert(keyPair, signatureAlgorithm, userID, true);

      if (result == null) {

        throw new Exception(); // Throw an Exception to signal test has failed

      }


      System.out.println("Delegated User Private Key:");
      sc.writeKey(System.out, keyPair.getPrivate());

      System.out.println("\nDelegated User Certificate from CA Server:");

      sc.writeCertificate(System.out, result);

    } catch (IllegalArgumentException ex) {

      System.err.printf(ex.getLocalizedMessage());

    }

  }

  public void multiTestGetCert()
    throws Exception {

    System.out.println("multi getCert");

    if (true) {
      KeyPair keyPair = sc.generateKeyPair("RSA", 2048);
      System.out.println("Looping now");
      String uriSpec = "http://one-test.contrail.rl.ac.uk:8080/ca/credential/fuser";

//    "http://localhost:8080/ca/credential/user"; // "https://one-test.contrail.rl.ac.uk/online-ca/credential";


      String signatureAlgorithm = "SHA256withRSA";
      String username = "coordinator";
      String password = "contrail";
      String actionPoint = "";
      String proxyHost = null;
      String proxyPortSpec = null;
      String proxyScheme = null;
      CertClient instance = new CertClient(uriSpec, true, "truststorePath", "trustStorePassphrase");
      X509Certificate expResult = null;
      X509Certificate result = null;

      Calendar now = Calendar.getInstance();

      Date start = now.getTime();

      int j = 0;

      try {

        for (int i = 0; i < 1000; i++) {

          j = i;
          //System.out.printf("i = %d ", i);

          result = instance.getCert(keyPair, signatureAlgorithm, username, password,
            actionPoint, /* proxyHost, proxyPortSpec, proxyScheme, */ true);

          sc.writeCertificate(result, String.format("/tmp/user%d.crt", i));


        }

      } catch (HttpException ex) {

        System.err.println(ex.getLocalizedMessage());

        throw new Exception();

      } catch (IOException ex) {

        System.err.println("IOE[[");
        System.err.println(ex.getLocalizedMessage());
        ex.printStackTrace();
        System.err.println("]]IOE");

      } catch (IllegalArgumentException ex) {

        System.err.println("IAE");
        System.err.printf(ex.getLocalizedMessage());

      }


      Calendar end = Calendar.getInstance();
      Date finish = end.getTime();

      System.out.printf("%ni=%d Started at %s, finished at %s.%n", j, start, finish);

    }


  }
}
