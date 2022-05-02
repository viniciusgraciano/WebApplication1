using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace Criptografia.Crypto
{
    public class EncryptedData
    {
        private enum EncryptionMethods
        {
            Aes256CbcPkcs7
        }

        private static EncryptionMethods DefaultEncryptionMethod = EncryptionMethods.Aes256CbcPkcs7;
        private EncryptionMethods Method { get; set; }
		public string Key { get { return Convert.ToBase64String (_key); } }

        /// <summary>
        /// Encryption key
        /// </summary>
        private byte[] _key;
        
        /// <summary>
        /// Initialization vector if required for the encryption method.
        /// </summary>
        private byte[] _iv;

        /// <summary>
        /// Base64-encoded representation of the encrypted data.
        /// </summary>
        private byte[] _data;
        
        /// <summary>
        /// Encrypts the given data with the default encryption method.
        /// </summary>
        /// <param name="dataToEncrypt"></param>
        public EncryptedData(string dataToEncrypt)
        {
            EncryptData(dataToEncrypt);
        }

        /// <summary>
        /// Encrypts the given byte data with the default encryption method.
        /// </summary>
        /// <param name="dataToEncrypt"></param>
        public EncryptedData(byte[] dataToEncrypt)
        {
            EncryptData(dataToEncrypt);
        }

        /// <summary>
        /// Encrypts the data with the given key. The key must be appropiate for the encryption method.
        /// </summary>
        /// <param name="dataToEncrypt"></param>
        /// <param name="encryptionKey"></param>
        internal EncryptedData(string dataToEncrypt, byte[] encryptionKey)
        {
            _key = encryptionKey;
            EncryptData(dataToEncrypt);
        }

        internal EncryptedData(byte[] dataToEncrypt, byte[] encryptionKey)
        {
            _key = encryptionKey;
            EncryptData(dataToEncrypt);
        }
        
        private void EncryptData(string dataToEncrypt)
        {
            EncryptData(Encoding.UTF8.GetBytes(dataToEncrypt));
        }

        private void EncryptData(byte[] dataToEncrypt)
        {
            Method = DefaultEncryptionMethod;
            switch (Method)
            {
                case EncryptionMethods.Aes256CbcPkcs7:
                    EncryptDataAes256CbcPkcs7(dataToEncrypt);
                    break;

                default:
                    throw new NotImplementedException("Encryption method has not been implemented");
            }
        }

        private void EncryptDataAes256CbcPkcs7(byte[] dataToEncrypt)
        {
            if (_key != null && _key.Length != 32)
                throw new Exception("Explicit data encryption key is not of required length for encryption method");
            
            if (_key == null)
            {
                // No explicit key was provided, we're going to generate our own.
                _key = new byte[32];
                RandomUtil.SecureRandomBc.NextBytes(_key);
            }

            _iv = new byte[16];
            RandomUtil.SecureRandomBc.NextBytes(_iv);

            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesFastEngine()), new Pkcs7Padding());
            cipher.Init(true, new ParametersWithIV(new KeyParameter(_key), _iv));

            _data = cipher.DoFinal(dataToEncrypt);
        }

        /// <summary>
        /// Raw byte array of the encrypted data.
        /// </summary>
        /// <returns></returns>
        internal byte[] ToBytes()
        {
            using (var memStream = new MemoryStream())
            {
                memStream.WriteByte((byte)(int)Method);
                memStream.Write(_iv, 0, _iv.Length);
                memStream.Write(_data, 0, _data.Length);

                return memStream.ToArray();
            }
        }

        /// <summary>
        /// Serializes the encrypted data into a base64 encoded string.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return Convert.ToBase64String(ToBytes());
        }

        public static string DecryptData(string encryptionKey, string serializedEncryptedData)
        {
            return Encoding.UTF8.GetString(DecryptDataAsBytes(encryptionKey, serializedEncryptedData));
        }

        public static byte[] DecryptDataAsBytes(string encryptionKey, string serializedEncryptedData)
        {
            var encryptionKeyBytes = Convert.FromBase64String(encryptionKey);
            var encryptedData = Convert.FromBase64String(serializedEncryptedData);
            return DecryptDataAsBytes(encryptionKeyBytes, encryptedData);
        }

        internal static byte[] DecryptDataAsBytes(byte[] encryptionKey, byte[] encryptedData)
        {
            using (var outputStream = new MemoryStream())
            using (var encryptedDataStream = new MemoryStream(encryptedData))
            {
                var methodByte = encryptedDataStream.ReadByte();
                if (methodByte < 0)
                    throw new Exception("Unexpected end of encrypted data");
                var method = (EncryptionMethods)methodByte;
                
                switch (method)
                {
                    case EncryptionMethods.Aes256CbcPkcs7:
                        DecryptDataAes256CbcPkcs7(encryptionKey, encryptedDataStream, outputStream);
                        break;
                    default:
                        throw new Exception("Unexpected data encryption method");
                }

                return outputStream.ToArray();
            }
        }

        /// <summary>
        /// Decrypt AES256-CBC with PKCS7 padding data
        /// </summary>
        /// <param name="encryptionKey"></param>
        /// <param name="encryptedDataStream"></param>
        /// <param name="outputStream"></param>
        private static void DecryptDataAes256CbcPkcs7(
            byte[] encryptionKey, Stream encryptedDataStream, Stream outputStream)
        {
            if (encryptionKey.Length != 32)
                throw new Exception("AES256 encryption key not of expected length");

            var iv = new byte[16];
            var ivBytesRead = encryptedDataStream.Read(iv, 0, 16);
            if (ivBytesRead != 16)
                throw new Exception("Unexpected IV");

            // The rest of the data stream is the encrypted data itself.

            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesFastEngine()), new Pkcs7Padding());
            cipher.Init(false, new ParametersWithIV(new KeyParameter(encryptionKey), iv));
            
            while (true)
            {
                var buffer = new byte[4096];
                var dataBytesRead = encryptedDataStream.Read(buffer, 0, 4096);
                if (dataBytesRead == 0)
                    break;
                
                var processedBytes = cipher.ProcessBytes(buffer, 0, dataBytesRead);
                if (processedBytes != null)
                    outputStream.Write(processedBytes, 0, processedBytes.Length);
            }
            var finalBytes = cipher.DoFinal();
            outputStream.Write(finalBytes, 0, finalBytes.Length);
        }
    }
}