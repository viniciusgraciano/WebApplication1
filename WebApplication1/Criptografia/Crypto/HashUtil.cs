using System;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;

namespace Criptografia.Crypto
{
    public static class HashUtil
    {
        /// <summary>
        /// Generates a SHA256 hash in hexadecimal format (uppercase).
        /// </summary>
        /// <param name="stringToHash"></param>
        /// <returns></returns>
        public static string Sha256(string stringToHash)
        {
            return Convert.ToBase64String(Sha256AsBytes(stringToHash));
        }

        /// <summary>
        /// Generates a SHA256 hash.
        /// </summary>
        /// <param name="stringToHash"></param>
        /// <returns></returns>
        private static byte[] Sha256AsBytes(string stringToHash)
        {
            var digest = new Sha256Digest();
            var returnBytes = new byte[digest.GetDigestSize()];
            var bytesToDigest = Encoding.UTF8.GetBytes(stringToHash);
            digest.BlockUpdate(bytesToDigest, 0, bytesToDigest.Length);
            digest.DoFinal(returnBytes, 0);
            return returnBytes;
        }

        /// <summary>
        /// Generates a SHA512 hash in hexadecimal format (uppercase).
        /// </summary>
        /// <param name="stringToHash"></param>
        /// <returns></returns>
        public static string Sha512(string stringToHash)
        {
            return Convert.ToBase64String(Sha512AsBytes(stringToHash));
        }

        /// <summary>
        /// Generates a SHA512 hash.
        /// </summary>
        /// <param name="stringToHash"></param>
        /// <returns></returns>
        private static byte[] Sha512AsBytes(string stringToHash)
        {
            var digest = new Sha512Digest();
            var returnBytes = new byte[digest.GetDigestSize()];
            var bytesToDigest = Encoding.UTF8.GetBytes(stringToHash);
            digest.BlockUpdate(bytesToDigest, 0, bytesToDigest.Length);
            digest.DoFinal(returnBytes, 0);
            return returnBytes;
        }

        /// <summary>
        /// Generates a client-side hash of the recovery password that is sent to the management API. 
        /// </summary>
        /// <param name="username"></param>
        /// <param name="recoveryPassword"></param>
        /// <returns></returns>
        public static string GenerateServerManagerRecoveryPasswordHash(string username, string recoveryPassword)
        {
            const char padChar = '!';
            const string label = "ServerManager";
            const int iterations = 64000;
            
            return GeneratePasswordHash(label, padChar, iterations, username, recoveryPassword);
        }

        /// <summary>
        /// Generates a client-side hash of the recovery password that is sent to the server API.
        /// </summary>
        /// <param name="username"></param>
        /// <param name="recoveryPassword"></param>
        /// <returns></returns>
        public static string GenerateServerRecoveryPasswordHash(string username, string recoveryPassword)
        {
            const char usernamePadChar = ']';
            const string label = "Server";
            const int iterations = 64000;
            
            return GeneratePasswordHash(label, usernamePadChar, iterations, username, recoveryPassword);
        }

        /// <summary>
        /// Generates a client-side hash of the recovery password that is sent to the server API.
        /// </summary>
        /// <param name="username"></param>
        /// <param name="recoveryPassword"></param>
        /// <returns></returns>
        public static string GenerateDatabaseBackupPasswordHash(string username, string recoveryPassword)
        {
            const char padChar = '&';
            const string label = "DatabaseBackup";
            const int iterations = 64000;
            
            return GeneratePasswordHash(label, padChar, iterations, username, recoveryPassword);
        }

        /// <summary>
        /// Generates a client-side hash to be used for encrypting the device backup data.
        /// This is intended to be stored locally on the second device (phone).
        /// </summary>
        /// <param name="username"></param>
        /// <param name="recoveryPassword"></param>
        /// <returns></returns>
        public static string GenerateDeviceBackupPasswordHash(string username, string recoveryPassword)
        {
            const char padChar = '=';
            const string label = "DeviceBackup";
            const int iterations = 10000;
            
            return GeneratePasswordHash(label, padChar, iterations, username, recoveryPassword);
        }

        /// <summary>
        /// Generates a client-side hash to be saved by the server, used to confirm validity of the recovery key.
        /// </summary>
        /// <param name="username"></param>
        /// <param name="recoveryPassword"></param>
        /// <returns></returns>
        public static string GenerateDeviceBackupPasswordCheckHash(string username, string recoveryPassword)
        {
            const char padChar = '£';
            const string label = "DeviceBackupCheck";
            const int iterations = 10000;
            
            return GeneratePasswordHash(label, padChar, iterations, username, recoveryPassword);
        }

        /// <summary>
        /// Generates a hash of the authentication details, so that the original username and password are not
        /// transmitted in the clear. 
        /// 
        /// Note that this does NOT use a random salt. These should still be hashed with a random 
        /// salt before storage by a server.
        /// </summary>
        /// <param name="label"></param>
        /// <param name="paddingChar"></param>
        /// <param name="iterations"></param>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        private static string GeneratePasswordHash(string label, char paddingChar, int iterations, 
            string username, string password)
        {
            // Pad the username with an application-specific char to the server's maximum allowable username length
            const int padLength = 255;
            
            var paddedUsername = label + username.ToLower().PadRight(padLength, paddingChar);
            var passwordConcatenation = label + paddedUsername + password;

            var hashPassword = Convert.ToBase64String(Sha512AsBytes(passwordConcatenation));
            var hashSalt = Convert.ToBase64String(Sha256AsBytes(paddedUsername));

            return PasswordHash.CreateHash(hashPassword, iterations, hashSalt);
        }
    }
}
