using Criptografia.Crypto;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Configuration;
using System.Text; 

namespace Test.Criptografia
{
    [TestClass]
    public class EncryptedDataWithKeyPairTests
    {
        private const string panEnc2 = "Tgu98Y+Qd5kNTpPy+i/lMj/5cWIvaIwpNOE8YD2eg8QBMc6QLpD4CvVh2KKPP28LtbywURKHfY4WDNd6VETq5IAzwamTbJ6VoLZd9a2A+NCmvQubMxMEX2y/TY0fbLTqR6XaHPgVvBlIIsg5AoTCPJ+Xih8t6zvRz6irWYxlGZ2p4n461Ne9Thpl4yLNHoAfhJtAbdI0mjrLBG5OCvSi0g6GpXuPwj3P886+E9V6v63Biwx1R1a2EHxR+52jZRKRpEN6BhlGzw8wL4fpHq8JVnQZxOoMpnTc52oh18OsIIRw1rP9/WJJPU5+1kK80/F+162t45OZRZBxZZTXArKAUg==";
        private const string TestString = "5092920000074713";

        private string chavePublica;
        private string chavePrivada;

        public EncryptedDataWithKeyPairTests()
        {
            this.chavePublica = $"-----BEGIN PUBLIC KEY-----\r\n{ConfigurationManager.AppSettings["RSA_CHAVE_PUBLICA"]}\r\n-----END PUBLIC KEY-----";
            this.chavePrivada = $"-----BEGIN PRIVATE KEY-----\r\n{ConfigurationManager.AppSettings["RSA_CHAVE_PRIVADA"]}\r\n-----END PRIVATE KEY-----";
        }

        [TestMethod]
        public void GerarPardeChaves()
        {
            var keypair = AsymmetricCryptoUtil.GenerateKeyPair();

            var textoAserEncriptado = "5092920000074713";

            var encryptedDataWithKeyPair = new EncryptedDataWithKeyPair(textoAserEncriptado, keypair.PublicPem);
            var encryptedDataWithKeyPairString = encryptedDataWithKeyPair.ToString();
             

            var decryptedTestString = EncryptedDataWithKeyPair.DecryptData(
                encryptedDataWithKeyPairString, keypair.PrivatePem);
 
            Assert.AreEqual(textoAserEncriptado, decryptedTestString);
        }

        [TestMethod]
        public void GerarPardeChavesXML()
        {
            RsaServico servico = new RsaServico();

            var publicKey = servico.GetPublicKey();
            var privateKey = servico.GetPrivateKey();

            var texto = "teste criptografia xml";

            var textEnc = RsaServico.EncryptFromXml(texto, publicKey);
            var textDec = RsaServico.DecryptFromXml(textEnc, privateKey);

            Assert.IsTrue(texto == textDec);
        }

        [TestMethod]
        public void EncryptionRsaServico()
        {
            var keypair = AsymmetricCryptoUtil.GenerateKeyPair();
            var texto = "5092920000074713";

            var textEnc = RsaServico.EncryptFromPem(texto, keypair.PublicPem);
            var textDec = RsaServico.DecryptFromPem(textEnc, keypair.PrivatePem);

            Assert.IsTrue(texto == textDec);
        }

        [TestMethod]
        public void DescryptPanRsaServico()
        {
            var panDecript = RsaServico.DecryptFromPem(panEnc2, chavePrivada);

            Assert.IsTrue(panDecript == "5092920000074713", "Erro");
        }

        [TestMethod]
        public void DescryptPan()
        {
           var panDecript =  EncryptedDataWithKeyPair.DecryptData(
                panEnc2, chavePrivada);

            Assert.IsTrue(panDecript != panEnc2, "Erro");
        }

        [TestMethod]
        public void TestEncryptedDataWithKeyPairRsaString()
        {
            var textoAserEncriptado = "5092920000074713";

            var encryptedDataWithKeyPair = new EncryptedDataWithKeyPair(textoAserEncriptado, chavePublica);
            var encryptedDataWithKeyPairString = encryptedDataWithKeyPair.ToString();

           // Assert.IsTrue(encryptedDataWithKeyPairString == panEnc);

            var decryptedTestString = EncryptedDataWithKeyPair.DecryptData(
                encryptedDataWithKeyPairString, chavePrivada);

            Assert.AreEqual(textoAserEncriptado, decryptedTestString);
        }

        [TestMethod]
        public void TestEncryptedDataWithKeyPairRsaBytes()
        {
            var encryptedDataWithKeyPair = new EncryptedDataWithKeyPair(
                Encoding.UTF8.GetBytes(TestString), chavePublica);
            var encryptedDataWithKeyPairString = encryptedDataWithKeyPair.ToString();

            Assert.IsNotNull(encryptedDataWithKeyPair.EncryptedKey);

            var decryptedTestBytes = EncryptedDataWithKeyPair.DecryptDataAsBytes(
                encryptedDataWithKeyPairString, chavePrivada);

            Assert.AreEqual(TestString, Encoding.UTF8.GetString(decryptedTestBytes));
        }

        [TestMethod]
        public void TestEncryptedDataWithKeyPairRsaDecrypt()
        {
            var decryptedTestString = EncryptedDataWithKeyPair.DecryptData(panEnc2, chavePrivada);
            Assert.AreEqual("5092920000074713", decryptedTestString);
        }

        [TestMethod]
        public void TestEncryptedDataWithKeyPairSignedRsaString()
        {
            var encryptedDataWithKeyPair = new EncryptedDataWithKeyPairSigned(
                TestString, chavePublica, chavePrivada);
            var encryptedDataWithKeyPairString = encryptedDataWithKeyPair.ToString();

            Assert.IsNotNull(encryptedDataWithKeyPairString);

            var decryptedTestString = EncryptedDataWithKeyPairSigned.DecryptData(
                encryptedDataWithKeyPairString, chavePrivada, chavePublica);

            Assert.AreEqual(TestString, decryptedTestString);
        }

        [TestMethod]
        public void TestEncryptedDataWithKeyPairSignedRsaDecrypt()
        {
              var decryptedTestString = EncryptedDataWithKeyPairSigned.DecryptData(
                panEnc2, chavePrivada, chavePublica);

            Assert.AreEqual(TestString, decryptedTestString);
        }
    }
}
