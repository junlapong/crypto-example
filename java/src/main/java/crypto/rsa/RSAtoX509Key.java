package crypto.rsa;

//***************************************************************
//
// RSAtoX509Key.java
// ASN.1 RSAPublicKey to ASN.1 SubjectPublicKeyInfo converter
//
// Copyright (C) 2006     JavaScience Consulting
//
//****************************************************************

import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.math.BigInteger;

// ---  Utility class to convert asn.1 RSAPublicKey to asn.1 SubjectPublicKeyInfo
// ---  data sequences in asn.1 are big-endian ordered (no reversal in Java required)
// ---  Writes asn.1 encoded SubjecPublicKeyInfo output file
// ---  Displays modulus and exponent and SubjectPublicKeyInfo encoded blob

public class RSAtoX509Key {

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java  RSAtoX509Key <RSAPublicKey file>  [SubjectPublicKeyInfo_pubkey]");
            return;
        }

        RSAPublicKey key = (RSAPublicKey) RSAtoX509Key.getPublicKey(args[0]);
        
        if (key != null) {

            System.out.println("\n---- Public key data for '" + args[0] + "' ----") ;

            BigInteger mod = key.getModulus();
            System.out.println("\nModulus: (base 10)\n" + mod.toString());
            System.out.println("\nModulus: (hex)");
            displayData(mod.toByteArray());

            BigInteger exp = key.getPublicExponent();
            System.out.println("\nPublic Exponent:\n" + exp.toString());
            System.out.println("\nSubjectPublicKeyInfo encoding:");
            displayData(key.getEncoded());

            if (args.length == 2) {

                try {
                    FileOutputStream fos = new FileOutputStream(args[1]);
                    fos.write(key.getEncoded());        //write the asn.1 SubjecPublickeyInfo
                    fos.close();
                    System.out.println("Wrote SubjectPublicKeyInfo file '" + args[1] + "'") ;
                }
                catch(IOException ex) {
                    System.err.println(ex);
                }
            }
        }
        else {
            System.out.println("FAILED to get PublicKey from file '" + args[0] + "'") ;
        }
    }

    public static PublicKey getPublicKey (String mspublickeyblobfile) {
        
        File blobfile = new File(mspublickeyblobfile);

        if (!blobfile.exists()) {
            return null;    
        }

        int blobsize = ((int) blobfile.length());
        byte[] blobdata = new byte[blobsize];

        try {
            FileInputStream freader = new FileInputStream(blobfile);
            freader.read(blobdata, 0, blobsize) ;
            freader.close();
            return getPublicKey(blobdata);
        }
        catch(IOException ioe) {
            return null;
        }
    }


    public static PublicKey getPublicKey (byte[] rsapublickey) {

        int blobsize = rsapublickey.length; 
        DataInputStream dis = null;
        int jint = 0 ; // int to represent unsigned byte or unsigned short
        int datacount = 0;

        try {

            //--- Try to read the ANS.1 encoded RSAPublicKey blob -------------
            ByteArrayInputStream bis = new ByteArrayInputStream(rsapublickey);
            dis = new DataInputStream(bis);

            if (dis.readByte() != 0x30) {   //asn.1 encoded starts with 0x30
                return null;
            }

            jint = dis.readUnsignedByte();  // asn.1 is 0x80 plus number of bytes representing data count
            
            if (jint == 0x81) {
                datacount = dis.readUnsignedByte();  //datalength is specified in next byte.  
            }
            else if (jint == 0x82) {  //bytes count for any supported keysize would be at most 2 bytes
                datacount = dis.readUnsignedShort();  //datalength is specified in next 2 bytes
            }
            else {
                return null;  //all supported publickey byte-sizes can be specified in at most 2 bytes
            }

            if ((jint - 0x80 + 2 + datacount) != blobsize) {   //sanity check for correct number of remaining bytes
                return null;
            }

            System.out.println("\nRead outer sequence bytes; validated outer asn.1 consistency ") ;

            // -------  Next attempt to read Integer sequence for modulus ------
            if (dis.readUnsignedByte() != 0x02) { //next byte read must be Integer asn.1 specifier
                return null;
            }

            jint = dis.readUnsignedByte();  // asn.1 is 0x80 plus number of bytes representing data count
            
            if (jint == 0x81) {
                datacount = dis.readUnsignedByte();  //datalength is specified in next byte.  
            }
            else if (jint == 0x82) { //bytes count for any supported keysize would be at most 2 bytes
                datacount = dis.readUnsignedShort();  //datalength is specified in next 2 bytes
            }
            else {
                return null;  //all supported publickey modulus byte-sizes can be specified in at most 2 bytes
            }

            // ---- next bytes are big-endian ordered modulus  -----
            byte[] modulus = new byte[datacount] ;
            int modbytes = dis.read(modulus) ;
            
            if (modbytes != datacount) {      // if we can read enought modulus bytes ...
                return null;
            }

            System.out.println("Read modulus") ;

            // -------  Next attempt to read Integer sequence for public exponent  ------
            if (dis.readUnsignedByte() != 0x02) {  //next byte read must be Integer asn.1 specifier
                return null;
            }

            datacount = dis.readUnsignedByte();  // size of modulus is specified in one byte
            byte[] exponent = new byte[datacount];
            int expbytes = dis.read(exponent);

            if (expbytes != datacount) {
                return null;
            }

            System.out.println("Read exponent");

            //----- Finally, create the PublicKey object from modulus and public exponent --------
            RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(new BigInteger(1, modulus), new BigInteger(1, exponent));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

            return pubKey;
        }
        catch(Exception exc) {
            return null;
        }
        finally {
            try {
                dis.close();
            }
            catch(Exception exc) {
            }
        }
    }
 
    private static void displayData(byte[] data) {
        
        int bytecon = 0;    //to get unsigned byte representation

        for (int i = 1; i <= data.length; i++) {

            bytecon = data[i - 1] & 0xFF;   // byte-wise AND converts signed byte to unsigned.

            if (bytecon < 16) {
                System.out.print("0" + Integer.toHexString(bytecon).toUpperCase() + " ");   // pad on left if single hex digit.
            }
            else {
                System.out.print(Integer.toHexString(bytecon).toUpperCase() + " ");   // pad on left if single hex digit.
            }
        
            if (i % 16 == 0) {
                System.out.println();
            }
        }

        System.out.println() ;
    }

}
