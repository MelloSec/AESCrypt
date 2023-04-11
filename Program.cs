using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AESCrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("Usage: AESCrypt.exe <keyword> <inputFile> <outputFile> <encrypt/decrypt>");
                return;
            }

            string keyword = args[3];
            string inputFile = args[1];
            string outputFile = args[2];
            string operation = args[0];

            if (operation == "encrypt")
            {
                byte[] inputData = File.ReadAllBytes(inputFile);
                byte[] encryptedData = EncryptAES(inputData, keyword);

                File.WriteAllBytes(outputFile, encryptedData);
                Console.WriteLine($"{inputFile} has been {operation}ed to {outputFile}");
            }
            else if (operation == "decrypt")
            {
                byte[] inputData = File.ReadAllBytes(inputFile);
                byte[] decryptedData = DecryptAES(inputData, keyword);

                File.WriteAllBytes(outputFile, decryptedData);
                Console.WriteLine($"{inputFile} has been {operation}ed to {outputFile}");
            }
            else
            {
                Console.WriteLine("Invalid operation. Mode must be either 'encrypt' or 'decrypt'");
                return;
            }
        }

        private static byte[] EncryptAES(byte[] inputData, string keyword)
        {
            byte[] key = Encoding.UTF8.GetBytes(keyword);
            byte[] iv = new byte[16];
            Buffer.BlockCopy(Encoding.UTF8.GetBytes(keyword), 0, iv, 0, iv.Length);

            if (key.Length * 8 != 128 && key.Length * 8 != 192 && key.Length * 8 != 256)
            {
                Console.WriteLine("Invalid key size. Key size must be 128, 192 or 256 bits");
                return null;
            }

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(inputData, 0, inputData.Length);
                        cs.FlushFinalBlock();
                    }

                    return ms.ToArray();
                }
            }
        }

        private static byte[] DecryptAES(byte[] inputData, string keyword)
        {
            byte[] key = Encoding.UTF8.GetBytes(keyword);
            byte[] iv = new byte[16];
            Buffer.BlockCopy(Encoding.UTF8.GetBytes(keyword), 0, iv, 0, iv.Length);

            if (key.Length * 8 != 128 && key.Length * 8 != 192 && key.Length * 8 != 256)
            {
                Console.WriteLine("Invalid key size. Key size must be 128, 192 or 256 bits");
                return null;
            }

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                using (MemoryStream ms = new MemoryStream(inputData))
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (MemoryStream output = new MemoryStream())
                        {
                            byte[] buffer = new byte[1024];
                            int bytesRead;

                            while ((bytesRead = cs.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                output.Write(buffer, 0, bytesRead);
                            }

                            return output.ToArray();
                        }
                    }
                }
            }
        }
    }
}


