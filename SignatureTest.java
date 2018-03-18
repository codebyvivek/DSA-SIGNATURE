import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
	import java.math.BigInteger;
	import java.security.KeyPair;
	import java.security.KeyPairGenerator;
	import java.security.NoSuchAlgorithmException;
	import java.security.interfaces.DSAParams;
	import sun.security.provider.DSAPrivateKey;
	import sun.security.provider.DSAPublicKey;

public class SignatureTest
{
   public static void main(String[] args)
   {
      try
      {

		/* To generate the key pair use it */
         if (args[0].equals("-genkeypair"))
         {

            KeyPairGenerator pairgen = KeyPairGenerator.getInstance("DSA","SUN");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG","SUN");
            pairgen.initialize(KEYSIZE, random);
            KeyPair keyPair = pairgen.generateKeyPair();
            DSAPrivateKey priv = (DSAPrivateKey) keyPair.getPrivate();
	    	DSAPublicKey pub = (DSAPublicKey) keyPair.getPublic();

	    	      /* The code to print the parameters of the public and private key */

	    	            DSAParams dsaParams = priv.getParams();
					    BigInteger prime = dsaParams.getP();
					    BigInteger subPrime = dsaParams.getQ();
					    BigInteger base = dsaParams.getG();
					    BigInteger x = priv.getX();
				        BigInteger y = pub.getY();
				        System.out.println("The p is : " + prime);
				        System.out.println("The q is : " + subPrime);
				        System.out.println("The g is : " + base);
				        System.out.println("The x is : " + x);
	                    System.out.println("The y is : " + y);

            /* to print the key pairs to the respective files
            Provide the file name in args[1] toprint the public key file
            Provide the file name in args[2] toprint the private key file
            */

            ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(args[1]));
            out.writeObject(keyPair.getPublic());
            out.close();
            out = new ObjectOutputStream(new FileOutputStream(args[2]));
            out.writeObject(keyPair.getPrivate());
            out.close();


	        }

	        /* To sign the document use this part
	        Provide the name of message file in args[1]
	        Provide the name of Signed data file in args[2]
	        Provide the name of private key file in args[3]

	        */
         else if (args[0].equals("-sign"))
         {
            ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(args[3]));
            PrivateKey privkey = (PrivateKey) keyIn.readObject();
            keyIn.close();

            Signature signalg = Signature.getInstance("DSA");
            signalg.initSign(privkey);

            File infile = new File(args[1]);
            InputStream in = new FileInputStream(infile);
            int length = (int) infile.length();
            byte[] message = new byte[length];
            in.read(message, 0, length);
            in.close();

            signalg.update(message);
            byte[] signature = signalg.sign();

            DataOutputStream out = new DataOutputStream(new FileOutputStream(args[2]));
            int signlength = signature.length;
            out.writeInt(signlength);
            out.write(signature, 0, signlength);
            out.write(message, 0, length);
            out.close();
         }

         /* To verify the document use this part
		 	        Provide the name of Signed message file in args[1]
		 	        Provide the name of public key file in args[2]
		 	        Provide the name of private key file in args[3]

	        */

         else if (args[0].equals("-verify"))
         {
            ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(args[2]));
            PublicKey pubkey = (PublicKey) keyIn.readObject();
            keyIn.close();

            Signature verifyalg = Signature.getInstance("DSA");
            verifyalg.initVerify(pubkey);

            File infile = new File(args[1]);
            DataInputStream in = new DataInputStream(new FileInputStream(infile));
            int signlength = in.readInt();
            byte[] signature = new byte[signlength];
            in.read(signature, 0, signlength);

            int length = (int) infile.length() - signlength - 4;
            byte[] message = new byte[length];
            in.read(message, 0, length);
            in.close();

            verifyalg.update(message);
            if (!verifyalg.verify(signature))
            System.out.print("not ");
            System.out.println("verified");
         }
      }
      catch (Exception e)
      {
         e.printStackTrace();
      }
   }

   private static final int KEYSIZE = 1024;
}