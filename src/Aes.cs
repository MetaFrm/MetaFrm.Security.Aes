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
            return ((IEncryptor)this).Encrypt(value, Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(IV));
        }
        byte[] IEncryptor.Encrypt(string value, byte[] key, byte[] IV)
        {
            byte[] encrypted;

            // Check arguments.
            ArgumentNullException.ThrowIfNull(value);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(IV);

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
            return Convert.ToBase64String(((IEncryptor)this).Encrypt(value, Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(IV)));
        }

        string IDecryptor.Decrypt(byte[] value, string key, string IV)
        {
            return ((IDecryptor)this).Decrypt(value, Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(IV));
        }
        string IDecryptor.Decrypt(byte[] value, byte[] key, byte[] IV)
        {
            // Check arguments.
            ArgumentNullException.ThrowIfNull(value);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(IV);

            // Declare the string used to hold
            // the decrypted text.

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
                return srDecrypt.ReadToEnd();
            }
        }
        string IDecryptor.DecryptFromBase64String(string value, string key, string IV)
        {
            return ((IDecryptor)this).Decrypt(Convert.FromBase64String(value), Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(IV));
        }

        private static byte[] GenerateKey(byte[] key)
        {
            byte[] keyNew = new byte[32];
            int length = Math.Min(key.Length, 32);
            Array.Copy(key, keyNew, length);
            // 남은 부분은 0으로 패딩됨
            return keyNew;
        }
        private static byte[] GenerateIV(byte[] IV)
        {
            byte[] ivNew = new byte[16];
            int length = Math.Min(IV.Length, 16);
            Array.Copy(IV, ivNew, length);
            // 남은 부분은 0으로 패딩됨
            return ivNew;
        }
    }
}