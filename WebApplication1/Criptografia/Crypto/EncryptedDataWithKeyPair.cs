using System;
using System.IO;
using System.Text;

namespace Criptografia.Crypto
{
    public class EncryptedDataWithKeyPair
    {
		public string EncryptedKey { get { return Convert.ToBase64String(_encryptedKey); } }

        private EncryptedData _encryptedData;
        private byte[] _encryptedKey;
        
        public EncryptedDataWithKeyPair(string dataToEncrypt, string publicKeyPem)
        {
            EncryptData(Encoding.UTF8.GetBytes(dataToEncrypt), publicKeyPem);
        }

        public EncryptedDataWithKeyPair(byte[] dataToEncrypt, string publicKeyPem)
        {
            EncryptData(dataToEncrypt, publicKeyPem);
        }

        private void EncryptData(byte[] dataToEncrypt, string publicKeyPem)
        {
            _encryptedData = new EncryptedData(dataToEncrypt);

            var encryptedKeyString = AsymmetricCryptoUtil.EncryptDataWithPublicKey(
                Convert.FromBase64String(_encryptedData.Key), publicKeyPem);
            _encryptedKey = encryptedKeyString;
        }

        public override string ToString()
        {
            return Convert.ToBase64String(ToBytes());
        }

        internal byte[] ToBytes()
        {
            using (var memStream = new MemoryStream())
            {
                memStream.Write(BitConverter.GetBytes(_encryptedKey.Length), 0, 4);
                memStream.Write(_encryptedKey, 0, _encryptedKey.Length);

                var encryptedData = _encryptedData.ToBytes();
                memStream.Write(encryptedData, 0, encryptedData.Length);

                return memStream.ToArray();
            }
        }

        public static string DecryptData(string serializedEncryptedData, string privateKeyPem)
        {
            return Encoding.UTF8.GetString(DecryptDataAsBytes(serializedEncryptedData, privateKeyPem));
        }

        public static byte[] DecryptDataAsBytes(string serializedEncryptedData, string privateKeyPem)
        {
            return DecryptDataAsBytes(Convert.FromBase64String(serializedEncryptedData), privateKeyPem);
        }

        internal static byte[] DecryptDataAsBytes(byte[] encryptedData, string privateKeyPem)
        {
            using (var encryptedDataStream = new MemoryStream(encryptedData))
            using (var encryptedDataWithoutKeyPair = new MemoryStream())
            {
                var encryptedKeyLengthBytes = new byte[4];
                var bytesRead = encryptedDataStream.Read(encryptedKeyLengthBytes, 0, 4);
                if (bytesRead == -1)
                    throw new Exception("Unexpected end of encrypted data (expected encrypted key size)");
                var encryptedKeyLength = BitConverter.ToInt32(encryptedKeyLengthBytes, 0);

                var encryptedKey = new byte[encryptedKeyLength];
                bytesRead = encryptedDataStream.Read(encryptedKey, 0, encryptedKeyLength);
                if (bytesRead != encryptedKeyLength)
                    throw new Exception("Unexpected end of encrypted data (expected encrypted key)");
                
                encryptedDataStream.CopyTo(encryptedDataWithoutKeyPair);

                var encryptionKey = AsymmetricCryptoUtil.DecryptDataWithPrivateKey(encryptedKey, privateKeyPem);
                return EncryptedData.DecryptDataAsBytes(encryptionKey, encryptedDataWithoutKeyPair.ToArray());
            }
        }
    }
}