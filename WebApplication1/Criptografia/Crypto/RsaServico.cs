using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace Criptografia.Crypto
{
    public class RsaServico
    {
        private static RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048);
        private RSAParameters _privateKey;
        private RSAParameters _publicKey;

        public RsaServico()
        {
            _privateKey = csp.ExportParameters(true);
            _publicKey = csp.ExportParameters(false);
        }
        public string GetPublicKey()
        {
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, _publicKey);

            return sw.ToString();
        }

        public string GetPrivateKey()
        {
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, _privateKey);

            return sw.ToString();
        }

        public static string EncryptFromXml(string plainText, string publicKeyxml)
        {
            var csp = new RSACryptoServiceProvider();
            csp.FromXmlString(publicKeyxml);
            var data = Encoding.Unicode.GetBytes(plainText);
            var cypher = csp.Encrypt(data, false);

            return Convert.ToBase64String(cypher);
        }

        public static string DecryptFromXml(string cypherText, string privateKeyxml)
        {
            var csp = new RSACryptoServiceProvider();
            csp.FromXmlString(privateKeyxml);

            var dataBytes = Convert.FromBase64String(cypherText);
            var plainText = csp.Decrypt(dataBytes, false);

            return Encoding.Unicode.GetString(plainText);
        }

        public static string EncryptFromPem(string cypherText, string publicKeyPEM)
        {
            //var csp = ImportPublicKeyFromPEM(publicKeyPEM);
            var csp = PublicKeyFromPemFile(publicKeyPEM);

            var dataBytes = Encoding.UTF8.GetBytes(cypherText);
            var plainText = csp.Encrypt(dataBytes, false);
            
            return Convert.ToBase64String(plainText);
        }
        public static string DecryptFromPem(string cypherText, string privateKeyPem)
        {
            var csp = PrivateKeyFromPemFile(privateKeyPem);
            var dataBytes = Convert.FromBase64String(cypherText);
            var plainText = csp.Decrypt(dataBytes, false);

            return Encoding.UTF8.GetString(plainText);
        }

        private static RSACryptoServiceProvider ImportPrivateKeyFromPEM(string pem)
        {
            AsymmetricKeyParameter param = ConvertPemToPrivateKey(pem);

            RSAParameters rsaParams =
            DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)param);

            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();// cspParams);
            csp.ImportParameters(rsaParams);
            return csp;
        }
        private static RSACryptoServiceProvider ImportPublicKeyFromPEM(string pem)
        {
            AsymmetricKeyParameter param = ConvertPemToPublicKey(pem);

            RSAParameters rsaParams =
            DotNetUtilities.ToRSAParameters((RsaKeyParameters)param);

            RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048);// cspParams);
            csp.ImportParameters(rsaParams);
            return csp;
        }
        private static AsymmetricKeyParameter ConvertPemToPublicKey(string pem)
        {
            using (var stringReader = new StringReader(pem))
            {
                var pemReader = new PemReader(stringReader);
                return PublicKeyFactory.CreateKey(pemReader.ReadPemObject().Content);
            }
        }
        private static AsymmetricKeyParameter ConvertPemToPrivateKey(string pem)
        {
            var pemReader = new PemReader(new StringReader(pem));
            var key = PrivateKeyFactory.CreateKey(pemReader.ReadPemObject().Content);
            return key;
        }


        public static RSACryptoServiceProvider PublicKeyFromPemFile(string publicKeyPEM)
        {
            using (TextReader publicKeyTextReader = new StringReader(publicKeyPEM))
            {
                var pr = new PemReader(publicKeyTextReader);
                RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(pr.ReadPemObject().Content);

                RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider(2048);
                RSAParameters parms = new RSAParameters();

                parms.Modulus = publicKeyParam.Modulus.ToByteArrayUnsigned();
                parms.Exponent = publicKeyParam.Exponent.ToByteArrayUnsigned();

                cryptoServiceProvider.ImportParameters(parms);

                return cryptoServiceProvider;
            }
        }
        public static RSACryptoServiceProvider PrivateKeyFromPemFile(String privateKeyPEM)
        {
            using (TextReader privateKeyTextReader = new StringReader(privateKeyPEM))
            {
               
                var pr = new PemReader(privateKeyTextReader);
                RsaPrivateCrtKeyParameters privateKeyParams = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(pr.ReadPemObject().Content);

                RSACryptoServiceProvider cryptoServiceProvider = new RSACryptoServiceProvider();
                RSAParameters parms = new RSAParameters();

                parms.Modulus = privateKeyParams.Modulus.ToByteArrayUnsigned();
                parms.P = privateKeyParams.P.ToByteArrayUnsigned();
                parms.Q = privateKeyParams.Q.ToByteArrayUnsigned();
                parms.DP = privateKeyParams.DP.ToByteArrayUnsigned();
                parms.DQ = privateKeyParams.DQ.ToByteArrayUnsigned();
                parms.InverseQ = privateKeyParams.QInv.ToByteArrayUnsigned();
                parms.D = privateKeyParams.Exponent.ToByteArrayUnsigned();
                parms.Exponent = privateKeyParams.PublicExponent.ToByteArrayUnsigned();

                cryptoServiceProvider.ImportParameters(parms);

                return cryptoServiceProvider;
            }
        }
    }
}
