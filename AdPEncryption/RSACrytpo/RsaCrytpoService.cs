using System;
using System.IO;
using System.Security.Cryptography;
using System.Xml.Serialization;
using System.Text;

namespace AdPEncryption.RSACrytpo
{
    public class RsaCrytpoService
    {
        private readonly RSACryptoServiceProvider _RsaCryptoServiceProvider;
        private readonly RSAParameters _privateKey;
        
        public RsaCrytpoService()
        {
            _RsaCryptoServiceProvider = new RSACryptoServiceProvider(2048);
            _privateKey = _RsaCryptoServiceProvider.ExportParameters(true);
        }

        public string GeneratePublicKey()
        {
            var publicKey = _RsaCryptoServiceProvider.ExportParameters(false);
            using (var stringwriter = new StringWriter())
            {
                var xs = new XmlSerializer(typeof(RSAParameters));
                xs.Serialize(stringwriter, publicKey);
                return stringwriter.ToString();
            }
        }

        public string Encrypt(string publicKey, string textToEncrypt)
        {
            RSAParameters pubKey;
            using (var stringReader = new StringReader(publicKey))
            {
                var xs = new XmlSerializer(typeof(RSAParameters));
                pubKey = (RSAParameters) xs.Deserialize(stringReader);
            }
            _RsaCryptoServiceProvider.ImportParameters(pubKey);
            var bytesToEncrypt = Encoding.Unicode.GetBytes(textToEncrypt);
            return Convert.ToBase64String(_RsaCryptoServiceProvider.Encrypt(bytesToEncrypt, RSAEncryptionPadding.Pkcs1));
        }

        public string Decrypt(string textToDecrypt)
        {
            var bytesToDecrypt = Convert.FromBase64String(textToDecrypt);
            _RsaCryptoServiceProvider.ImportParameters(_privateKey);
            var result = _RsaCryptoServiceProvider.Decrypt(bytesToDecrypt, RSAEncryptionPadding.Pkcs1);
            return Encoding.Unicode.GetString(result);
        }
    }
}
