using System;
using System.ComponentModel;
using System.IO;
using System.Text;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;
using PemReader = Org.BouncyCastle.Utilities.IO.Pem.PemReader;
using PemWriter = Org.BouncyCastle.Utilities.IO.Pem.PemWriter;

namespace Criptografia.Crypto
{
    public static class AsymmetricCryptoUtil
    {
        public static KeyPair GenerateKeyPair()
        {
            return GenerateKeyPair(KeyPair.KeyTypeDefault);
        }

        public static KeyPair GenerateKeyPair(KeyPair.KeyTypes type)
        {
            AsymmetricCipherKeyPair generatedKeyPair;
            switch (type)
            {
                case KeyPair.KeyTypes.Ecc:
                    generatedKeyPair = GenerateKeyPairEcc();
                    break;
                case KeyPair.KeyTypes.Rsa:
                    generatedKeyPair = GenerateKeyPairRsa();
                    break;
                default:
                    throw new InvalidEnumArgumentException("Invalid key type");
            }
            
            var pubKeyPem = ConvertPublicKeyToPem(generatedKeyPair.Public);
            var privKeyPem = ConvertPrivateKeyToPem(generatedKeyPair.Private);

            return new KeyPair(type, privKeyPem, pubKeyPem);
        }

        private static AsymmetricCipherKeyPair GenerateKeyPairEcc()
        {
            var oid = X962NamedCurves.GetOid("prime256v1");
            var generator = new ECKeyPairGenerator();
            var genParam = new ECKeyGenerationParameters(oid, RandomUtil.SecureRandomBc);
            generator.Init(genParam);
            return generator.GenerateKeyPair();
        }

        private static AsymmetricCipherKeyPair GenerateKeyPairRsa()
        {
            var generator = GeneratorUtilities.GetKeyPairGenerator("RSA");
            var generatorParams = new RsaKeyGenerationParameters(
                new BigInteger("10001", 16), RandomUtil.SecureRandomBc, 2048, 112);
            generator.Init(generatorParams);
            return generator.GenerateKeyPair();
        }
        
        private static string ConvertPublicKeyToPem(AsymmetricKeyParameter pubKey)
        {
            using (var stringWriter = new StringWriter())
            {
                var publicKeyInfo  = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubKey);
                var pemWriter = new PemWriter(stringWriter);
                PemObjectGenerator pemObject = new PemObject("PUBLIC KEY", publicKeyInfo.GetEncoded());
                pemWriter.WriteObject(pemObject);
                return stringWriter.ToString();
            }
        }

        private static string ConvertPrivateKeyToPem(AsymmetricKeyParameter privateKey)
        {
            using (var stringWriter = new StringWriter())
            {
                var pkcsgen = new Pkcs8Generator(privateKey);
                var pemwriter = new PemWriter(stringWriter);
                pemwriter.WriteObject(pkcsgen.Generate());
                return stringWriter.ToString();
            }
        }

        private static AsymmetricKeyParameter ConvertPemToPublicKey(string pem)
        {
            using (var stringReader = new StringReader(pem))
            {
                var pemReader = new PemReader(stringReader);
                return PublicKeyFactory.CreateKey(pemReader.ReadPemObject().Content);
            }
        }

        
        internal static AsymmetricKeyParameter ConvertPemToPrivateKey(string pem)
        {
            var pemReader = new PemReader(new StringReader(pem));
            var key = PrivateKeyFactory.CreateKey(pemReader.ReadPemObject().Content);
            return key;
        }

        public static string CreateSignature(string message, string privateKeyPem)
        {
            return Convert.ToBase64String(CreateSignature(Encoding.UTF8.GetBytes(message), privateKeyPem));
        }

        internal static byte[] CreateSignature(byte[] message, string privateKeyPem)
        {
            var privateKey = ConvertPemToPrivateKey(privateKeyPem);
            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(ConvertPemToPrivateKey(privateKeyPem));

            ISigner signer;
            switch (privateKeyInfo.PrivateKeyAlgorithm.Algorithm.Id)
            {
                case "1.2.840.10045.2.1":
                    // EC Key
                    signer = SignerUtilities.GetSigner("SHA256withECDSA");
                    break;

                case "1.2.840.113549.1.1.1":
                    // RSA key
                    signer = SignerUtilities.GetSigner("SHA256withRSA");
                    break;

                default:
                    throw new ArgumentException(
                        "Unsupported key type " + privateKeyInfo.PrivateKeyAlgorithm.Algorithm.Id, 
                        nameof(privateKeyPem));
            }

            signer.Init(true, privateKey);
            var stringToSignInBytes = message;
            signer.BlockUpdate(stringToSignInBytes, 0, stringToSignInBytes.Length);
            var signature = signer.GenerateSignature();
            return signature;
        }

        public static bool VerifySignature(string message, string signature, string publicKeyPem)
        {
            return VerifySignature(
                Encoding.UTF8.GetBytes(message), Convert.FromBase64String(signature), publicKeyPem);
        }

        internal static bool VerifySignature(byte[] message, byte[] signature, string publicKeyPem)
        {
            var publicKey = ConvertPemToPublicKey(publicKeyPem);
            var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);

            ISigner signer;
            switch (publicKeyInfo.AlgorithmID.Algorithm.Id)
            {
                case "1.2.840.10045.2.1":
                    // EC Key
                    signer = SignerUtilities.GetSigner("SHA256withECDSA");
                    break;
                case "1.2.840.113549.1.1.1":
                    // RSA Key
                    signer = SignerUtilities.GetSigner("SHA256withRSA");
                    break;
                default:
                    throw new ArgumentException(
                        "Unsupported key type " + publicKeyInfo.AlgorithmID.Algorithm.Id,
                        nameof(publicKey));
            }

            signer.Init(false, publicKey);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.VerifySignature(signature);
        }
        
        internal static byte[] EncryptDataWithPublicKey(byte[] data, string publicKeyPem)
        {
            var recipientPublicKey = ConvertPemToPublicKey(publicKeyPem);
            var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(recipientPublicKey);

            switch (publicKeyInfo.AlgorithmID.Algorithm.Id)
            {
//                case "1.2.840.10045.2.1":
//                    // EC Key
//                    break;
                case "1.2.840.113549.1.1.1":
                    // RSA Key
                    return EncryptDataWithPublicKeyRsa(data, (RsaKeyParameters)recipientPublicKey);
                default:
                    throw new ArgumentException(
                        "Unsupported key type " + publicKeyInfo.AlgorithmID.Algorithm.Id,
                        nameof(publicKeyPem));
            }
        }
        
        private static byte[] EncryptDataWithPublicKeyRsa(byte[] encryptedData, RsaKeyParameters publicKey)
        {
            var cipher = CipherUtilities.GetCipher("RSA//PKCS1Padding");
            cipher.Init(true, publicKey);
            return cipher.DoFinal(encryptedData);
        }
        
        internal static byte[] DecryptDataWithPrivateKey(byte[] encryptedData, string privateKeyPem)
        {
            var privateKey = ConvertPemToPrivateKey(privateKeyPem);
            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);

            switch (privateKeyInfo.PrivateKeyAlgorithm.Algorithm.Id)
            {
//                case "1.2.840.10045.2.1":
//                    // EC Key
//                    break;
                case "1.2.840.113549.1.1.1":
                    // RSA key
                    return DecryptDataWithPrivateKeyRsa(encryptedData, (RsaKeyParameters)privateKey);
                default:
                    throw new ArgumentException(
                        "Unsupported key type " + privateKeyInfo.PrivateKeyAlgorithm.Algorithm.Id,
                        nameof(privateKeyPem));
            }
        }

        private static byte[] DecryptDataWithPrivateKeyRsa(byte[] encryptedData, RsaKeyParameters privateKey)
        {
            var cipher = CipherUtilities.GetCipher("RSA//PKCS1Padding");
            cipher.Init(false, privateKey);
            return cipher.DoFinal(encryptedData);
        }
    }
}