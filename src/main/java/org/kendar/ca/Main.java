package org.kendar.ca;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.Scanner;

public class Main {
    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static KeyPairGenerator keyPairGenerator;
    private static KeyPair rootKeyPair;
    private static X500Name rootCertIssuer;
    private static Date startDate;
    private static Date endDate;
    private static X509Certificate rootCert;

    public static void main(String[] args) throws Exception {
        // Add the BouncyCastle Provider
        Security.addProvider(new BouncyCastleProvider());
        generateRootCertificate();
    }

    public static void generateRootCertificate() throws Exception {
        // Initialize a new KeyPair generator
        Scanner myInput = new Scanner( System.in );
        System.out.println("Key Algorithm: "+KEY_ALGORITHM);
        keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);

        // Set key size
        System.out.println("Key Size (2048/4096)");
        var keySize = myInput.nextInt();
        if(keySize!=2048 && keySize!=4096) throw new Exception("Unallowed key size");
        keyPairGenerator.initialize(keySize);

        // Setup start date to yesterday and end date for 1 year validity
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        startDate = calendar.getTime();


        System.out.println("Validity in days");
        var daysVailidy = myInput.nextInt();
        calendar.add(Calendar.DATE, daysVailidy);
        endDate = calendar.getTime();

        // First step is to create a root certificate
        // First Generate a KeyPair,
        // then a random serial number
        // then generate a certificate using the KeyPair
        rootKeyPair = keyPairGenerator.generateKeyPair();
        BigInteger rootSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

        System.out.println(". to select default");

        StringBuilder issuerString = new StringBuilder();
        System.out.println("Country [AU]:");
        String val = myInput.next();
        if(val.length()>2) throw new Exception("2 Letters country");
        if(val.equalsIgnoreCase("."))val = "AU";
        issuerString.append("C="+val.toUpperCase(Locale.ROOT));

        /*System.out.println("State or province [Some-State]:");
        val = myInput.next();
        if(val.equalsIgnoreCase("."))val = "Some-State";
        issuerString.append(",S="+val);*/

        System.out.println("Locality Name []:");
        val = myInput.next();
        if(!val.equalsIgnoreCase("."))issuerString.append(",L="+val);

        System.out.println("Org Name [Internet Widgits Pty Ltd]:");
        val = myInput.next();
        if(val.equalsIgnoreCase("."))val = "Internet Widgits Pty Ltd";
        issuerString.append(",O="+val);

        System.out.println("Org Unit Name []:");
        val = myInput.next();
        if(!val.equalsIgnoreCase("."))issuerString.append(",OU="+val);

        System.out.println("Common Name (e.g. server FQDN or YOUR name)[]:");
        val = myInput.next();
        if(!val.equalsIgnoreCase("."))issuerString.append(",CN="+val);

        System.out.println("Email []:");
        val = myInput.next();
        if(!val.equalsIgnoreCase("."))issuerString.append(",E="+val);


        // Issued By and Issued To same for root certificate
        rootCertIssuer = new X500Name(issuerString.toString());
        X500Name rootCertSubject = rootCertIssuer;

        System.out.println("Signature Algorithm: "+SIGNATURE_ALGORITHM);
        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER).build(rootKeyPair.getPrivate());
        X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(rootCertIssuer, rootSerialNum, startDate, endDate, rootCertSubject, rootKeyPair.getPublic());

        // Add Extensions
        // A BasicConstraint to mark root certificate as CA certificate
        JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
        rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        rootCertBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                rootCertExtUtils.createSubjectKeyIdentifier(rootKeyPair.getPublic()));


        rootCertBuilder.addExtension(
                Extension.extendedKeyUsage,
                false,
                new ExtendedKeyUsage(
                        new KeyPurposeId[] {
                                KeyPurposeId.id_kp_serverAuth,
                                KeyPurposeId.id_kp_clientAuth,
                                KeyPurposeId.id_kp_codeSigning,
                                KeyPurposeId.id_kp_timeStamping,
                                KeyPurposeId.id_kp_emailProtection,}));

        rootCertBuilder.addExtension(
                Extension.keyUsage,
                false,
                new X509KeyUsage(
                        X509KeyUsage.digitalSignature
                                | X509KeyUsage.nonRepudiation
                                | X509KeyUsage.cRLSign
                                | X509KeyUsage.keyCertSign
                                | X509KeyUsage.keyAgreement
                                | X509KeyUsage.keyEncipherment
                                | X509KeyUsage.dataEncipherment));

        // Create a cert holder and export to X509Certificate
        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
        rootCert = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(rootCertHolder);

        System.out.println("Output file name [ca]:");
        val = myInput.next();
        if(val.equalsIgnoreCase("."))val = "ca";

        System.out.println("Set the key password:");
        var password = myInput.next();

        writeCertToFileBase64Encoded(rootCert, val,rootKeyPair,password);
    }

    static void writeCertToFileBase64Encoded(Certificate certificate, String fileName, KeyPair rootKeyPair,String pass) throws Exception {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter writer  = new JcaPEMWriter(sw)) {
            writer.writeObject(certificate);
        }
        String pem = sw.toString();
        BufferedWriter bw = new BufferedWriter(new FileWriter(fileName+".pem"));
        bw.write(pem);
        bw.close();

        PrivateKey priv = rootKeyPair.getPrivate();


        var builder = new JcaPKCS8EncryptedPrivateKeyInfoBuilder(priv);


        var encryptorBuilder = new JcePKCSPBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC);

        var password = pass.toCharArray();
        var outputBuilder = encryptorBuilder.build(password);
        var privKeyObj = builder.build(outputBuilder);
        var fos = new FileOutputStream(fileName+".key");
        fos.write(privKeyObj.getEncoded());
        fos.flush();
        fos.close();

        /*sw = new StringWriter();
        try (JcaPEMWriter  writer  = new JcaPEMWriter(sw)) {
            writer.writeObject(priv);
        }
        pem = sw.toString();
        bw = new BufferedWriter(new FileWriter(fileName+".clear.key"));
        bw.write(pem);
        bw.close();*/
    }
}
