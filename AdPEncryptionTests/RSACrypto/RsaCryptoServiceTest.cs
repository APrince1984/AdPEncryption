using System;
using AdPEncryption.RSACrytpo;
using NUnit.Framework;

namespace AdPEncryptionTests.RSACrypto
{
    [TestFixture]
    public class RsaCryptoServiceTest
    {
        [Test]
        [Repeat(5)]
        public void GeneratePublicKey_ReturnsPublicKey()
        {
            var rsaCryptoService = new RsaCrytpoService();
            var pubKey = rsaCryptoService.GeneratePublicKey();
            Console.WriteLine(pubKey);
            Assert.IsNotNull(pubKey);
        }

        [Test]
        [Repeat(5)]
        public void Encrypt()
        {
            var rsaCryptoService = new RsaCrytpoService();
            var textToEncrypt = "This Is Some Random Text To Encrypt";
            var pubKey = rsaCryptoService.GeneratePublicKey();
            var encryptedText = rsaCryptoService.Encrypt(pubKey, textToEncrypt);
            Console.WriteLine(encryptedText);
            Assert.IsNotNull(encryptedText);
        }

        [Test]
        [Repeat(5)]
        public void DeCrypt()
        {
            var rsaCryptoService = new RsaCrytpoService();
            var textToEncrypt = "This Is Some Random Text To Encrypt";
            var pubKey = rsaCryptoService.GeneratePublicKey();
            var encryptedText = rsaCryptoService.Encrypt(pubKey, textToEncrypt);
            var decryptedText = rsaCryptoService.Decrypt(encryptedText);
            Console.WriteLine(decryptedText);
            Assert.AreEqual(textToEncrypt, decryptedText);
        }
    }
}
