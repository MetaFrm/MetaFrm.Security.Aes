using System.Security.Cryptography;
using System.Text;

namespace MetaFrm.Security
{
    /// <summary>
    /// AES 암호화
    /// </summary>
    public class Aes : IEncryptor, IDecryptor
    {
        byte[] IEncryptor.Encrypt(string value, string key, string IV)
        {
            return ((IEncryptor)this).Encrypt(value, UTF8Encoding.Default.GetBytes(key), UTF8Encoding.Default.GetBytes(IV));
        }
        byte[] IEncryptor.Encrypt(string value, byte[] key, byte[] IV)
        {
            byte[] encrypted;

            // Check arguments.
            if (value == null || value.Length <= 0)
                throw new ArgumentNullException(nameof(value));
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException(nameof(key));
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException(nameof(IV));

            // Create an Aes object
            // with the specified key and IV.
            using (System.Security.Cryptography.Aes aesAlg = System.Security.Cryptography.Aes.Create())
            {
                aesAlg.Key = GenerateKey(key);
                aesAlg.IV = GenerateIV(IV);

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using MemoryStream msEncrypt = new();
                using CryptoStream csEncrypt = new(msEncrypt, encryptor, CryptoStreamMode.Write);
                using (StreamWriter swEncrypt = new(csEncrypt))
                {
                    //Write all data to the stream.
                    swEncrypt.Write(value);
                }
                encrypted = msEncrypt.ToArray();
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }
        string IEncryptor.EncryptToBase64String(string value, string key, string IV)
        {
            return Convert.ToBase64String(((IEncryptor)this).Encrypt(value, UTF8Encoding.Default.GetBytes(key), UTF8Encoding.Default.GetBytes(IV)));
        }

        string IDecryptor.Decrypt(byte[] value, string key, string IV)
        {
            return ((IDecryptor)this).Decrypt(value, UTF8Encoding.Default.GetBytes(key), UTF8Encoding.Default.GetBytes(IV));
        }
        string IDecryptor.Decrypt(byte[] value, byte[] key, byte[] IV)
        {
            // Check arguments.
            if (value == null || value.Length <= 0)
                throw new ArgumentNullException(nameof(value));
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException(nameof(key));
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException(nameof(IV));

            // Declare the string used to hold
            // the decrypted text.
            string? result = null;

            // Create an Aes object
            // with the specified key and IV.
            using (System.Security.Cryptography.Aes aesAlg = System.Security.Cryptography.Aes.Create())
            {
                aesAlg.Key = GenerateKey(key);
                aesAlg.IV = GenerateIV(IV);

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using MemoryStream msDecrypt = new(value);
                using CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read);
                using StreamReader srDecrypt = new(csDecrypt);
                // Read the decrypted bytes from the decrypting stream
                // and place them in a string.
                result = srDecrypt.ReadToEnd();
            }

            return result;
        }
        string IDecryptor.DecryptFromBase64String(string value, string key, string IV)
        {
            return ((IDecryptor)this).Decrypt(Convert.FromBase64String(value), UTF8Encoding.Default.GetBytes(key), UTF8Encoding.Default.GetBytes(IV));
        }

        private static byte[] GenerateKey(byte[] key)
        {
            byte[] keyNew = new byte[32];

            int j = -1;
            for (int i = 0; i < 32; i++)
            {
                if (32 > j && key.Length > (j + 1))
                    j += 1;
                else
                    break;
                //j = 0;

                keyNew[i] = key[j];
            }

            return keyNew;
        }
        private static byte[] GenerateIV(byte[] IV)
        {
            byte[] ivNew = new byte[16];

            int j = -1;
            for (int i = 0; i < 16; i++)
            {
                if (16 > j && IV.Length > (j + 1))
                    j += 1;
                else
                    break;
                //j = 0;

                ivNew[i] = IV[j];
            }

            return ivNew;
        }
    }
}