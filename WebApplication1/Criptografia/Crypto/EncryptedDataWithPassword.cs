using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Criptografia.Crypto
{
    /// <summary>
    /// Encrypts data with the given password, authenticated with hmac.
    /// </summary>
    public class EncryptedDataWithPassword
    {
        private byte[] _encryptedData;
        private byte[] _encryptedDataHmac;
        
        public EncryptedDataWithPassword(string dataToEncrypt, string password)
        {
            EncryptData(Encoding.UTF8.GetBytes(dataToEncrypt), password);
        }

        public EncryptedDataWithPassword(byte[] dataToEncrypt, string password)
        {
            EncryptData(dataToEncrypt, password);
        }

        private void EncryptData(byte[] dataToEncrypt, string password)
        {
            // Generate the encryption key
            var hash = PasswordHash.CreateHash(password, 1, "");
            
            // Generate the authentication key
            var authKeyHash = PasswordHash.CreateHash(password, 2, "");
            var authKey = Convert.FromBase64String(authKeyHash);

            _encryptedData = new EncryptedData(dataToEncrypt, Convert.FromBase64String(hash)).ToBytes();
            
            var hmac = new HMac(new Sha256Digest());
            var mac = new byte[hmac.GetMacSize()];
            hmac.Init(new KeyParameter(authKey));
            hmac.BlockUpdate(_encryptedData, 0, _encryptedData.Length);
            hmac.DoFinal(mac, 0);
            _encryptedDataHmac = mac;
        }

        public override string ToString()
        {
            using (var memStream = new MemoryStream())
            {
                memStream.Write(BitConverter.GetBytes(_encryptedDataHmac.Length), 0, 4);
                memStream.Write(_encryptedDataHmac, 0, _encryptedDataHmac.Length);
                memStream.Write(_encryptedData, 0, _encryptedData.Length);

                return Convert.ToBase64String(memStream.ToArray());
            }
        }

        public static string DecryptData(string password, string serializedEncryptedData)
        {
            return Encoding.UTF8.GetString(DecryptDataAsBytes(serializedEncryptedData, password));
        }

        public static byte[] DecryptDataAsBytes(string serializedEncryptedData, string password)
        {
            var encryptedData = Convert.FromBase64String(serializedEncryptedData);

            using (var encryptedDataStream = new MemoryStream(encryptedData))
            {
                var hmacNumBytes = new byte[4];
                var bytesRead = encryptedDataStream.Read(hmacNumBytes, 0, 4);
                if (bytesRead != 4)
                    throw new Exception("Unexpected end of encrypted data (expected HMAC length)");
                var hmacLength = BitConverter.ToInt32(hmacNumBytes, 0);
                
                var givenMac = new byte[hmacLength];
                bytesRead = encryptedDataStream.Read(givenMac, 0, hmacLength);
                if (bytesRead != hmacLength)
                    throw new Exception("Unexpected end of encrypted data (expected HMAC)");

                // Can't think of a more elegant way to read the remaining bytes of the stream.
                byte[] ciphertext;
                using (var encryptedDataWithoutPassword = new MemoryStream())
                {
                    encryptedDataStream.CopyTo(encryptedDataWithoutPassword);
                    ciphertext = encryptedDataWithoutPassword.ToArray();
                }

                var encryptionKey = PasswordHash.CreateHash(password, 1, "");
                var authKey = Convert.FromBase64String(PasswordHash.CreateHash(password, 2, ""));

                var hmac = new HMac(new Sha256Digest());
                var calculatedMac = new byte[hmac.GetMacSize()];
                hmac.Init(new KeyParameter(authKey));
                hmac.BlockUpdate(ciphertext, 0, ciphertext.Length);
                hmac.DoFinal(calculatedMac, 0);

                if (!Arrays.ConstantTimeAreEqual(givenMac, calculatedMac))
                    throw new Exception("Encrypted data macs do not match");
                
                return EncryptedData.DecryptDataAsBytes(Convert.FromBase64String(encryptionKey), ciphertext);
            }
        }
    }
}