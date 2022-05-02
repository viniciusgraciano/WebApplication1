using System;
using System.IO;
using System.Text;

namespace Criptografia.Crypto
{
    public class EncryptedDataWithKeyPairSigned
    {
        private byte[] _signature;
        private EncryptedDataWithKeyPair _encryptedData;
        
        public EncryptedDataWithKeyPairSigned(string dataToEncrypt, string publicKeyPem, string privateKeyPem)
        {
            EncryptData(Encoding.UTF8.GetBytes(dataToEncrypt), publicKeyPem, privateKeyPem);
        }
        
        private void EncryptData(byte[] dataToEncrypt, string publicKeyPem, string privateKeyPem)
        {
            _signature = AsymmetricCryptoUtil.CreateSignature(dataToEncrypt, privateKeyPem);
            _encryptedData = new EncryptedDataWithKeyPair(dataToEncrypt, publicKeyPem);
        }

        public override string ToString()
        {
            return Convert.ToBase64String(ToBytes());
        } 

        internal byte[] ToBytes()
        {
            using (var memStream = new MemoryStream())
            {
                memStream.Write(BitConverter.GetBytes(_signature.Length), 0, 4);
                memStream.Write(_signature, 0, _signature.Length);

                var encryptedData = _encryptedData.ToBytes();
                memStream.Write(encryptedData, 0, encryptedData.Length);

                return memStream.ToArray();
            }
        }

        public static string DecryptData(string serializedEncryptedData, string privateKeyPem, string publicKeyPem)
        {
            return Encoding.UTF8.GetString(
                DecryptDataAsBytes(Convert.FromBase64String(serializedEncryptedData), privateKeyPem, publicKeyPem));
        }

        private static byte[] DecryptDataAsBytes(byte[] encryptedData, string privateKeyPem, string publicKeyPem)
        {
            using (var encryptedDataStream = new MemoryStream(encryptedData))
            using (var encryptedDataWithoutKeyPair = new MemoryStream())
            {
                var signatureLengthBytes = new byte[4];
                var bytesRead = encryptedDataStream.Read(signatureLengthBytes, 0, 4);
                if (bytesRead == -1)
                    throw new Exception("Unexpected end of encrypted data (expected encrypted key size)");
                var signatureLength = BitConverter.ToInt32(signatureLengthBytes, 0);

                var signature = new byte[signatureLength];
                bytesRead = encryptedDataStream.Read(signature, 0, signatureLength);
                if (bytesRead != signatureLength)
                    throw new Exception("Unexpected end of encrypted data (expected encrypted key)");

                encryptedDataStream.CopyTo(encryptedDataWithoutKeyPair);

                var decryptedData = EncryptedDataWithKeyPair.DecryptDataAsBytes(
                    encryptedDataWithoutKeyPair.ToArray(), privateKeyPem);

                var signatureVerified = AsymmetricCryptoUtil.VerifySignature(decryptedData, signature, publicKeyPem);
                if (!signatureVerified)
                    throw new Exception("Message could not be verified");
                return decryptedData;
            }
        }
    }
}