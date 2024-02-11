using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Usage: Program.exe <FolderPath> /e (encrypt) or /d (decrypt)");
            return;
        }

        string folderPath = args[0];
        string operation = args[1].ToLower();

        if (!Directory.Exists(folderPath))
        {
            Console.WriteLine("Invalid folder path.");
            return;
        }

        string password = null;

        switch (operation)
        {
            case "/e":
                password = GenerateRandomKey();
                SaveKeyToFile("encryptionKey.txt", password); // Save the key to a file
                EncryptFilesInFolder(folderPath, password);
                Console.WriteLine("Encryption complete.");
                break;
            case "/d":
                if (args.Length > 2)
                {
                    password = args[2];
                }
                else
                {
                    Console.Write("Enter the decryption key: ");
                    password = Console.ReadLine();
                }
                DecryptFilesInFolder(folderPath, password);
                Console.WriteLine("Decryption complete.");
                break;
            default:
                Console.WriteLine("Invalid operation. Use /e (encrypt) or /d (decrypt).");
                break;
        }
    }

    static void EncryptFilesInFolder(string folderPath, string password)
    {
        string[] files = Directory.GetFiles(folderPath, "*", SearchOption.AllDirectories);

        foreach (string filePath in files)
        {
            if (!IsSystemFile(filePath) && !IsExcludedFileType(filePath))
            {
                EncryptFile(filePath, password);
            }
        }
    }

    static void DecryptFilesInFolder(string folderPath, string password)
    {
        string[] encryptedFiles = Directory.GetFiles(folderPath, "*.encrypted", SearchOption.AllDirectories);

        foreach (string encryptedFilePath in encryptedFiles)
        {
            DecryptFile(encryptedFilePath, password);
        }
    }

    static bool IsSystemFile(string filePath)
    {
        var fileInfo = new FileInfo(filePath);
        return fileInfo.Attributes.HasFlag(FileAttributes.System);
    }

    static bool IsExcludedFileType(string filePath)
    {
        string[] excludedFileTypes = { ".dll", ".exe" };
        return excludedFileTypes.Contains(Path.GetExtension(filePath), StringComparer.OrdinalIgnoreCase);
    }

    static void EncryptFile(string filePath, string password)
    {
        using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
        {
            aesAlg.Key = GetKey(password);
            aesAlg.GenerateIV();

            using (FileStream fsIn = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            using (FileStream fsOut = new FileStream(filePath + ".encrypted", FileMode.Create, FileAccess.Write))
            using (ICryptoTransform encryptor = aesAlg.CreateEncryptor())
            using (CryptoStream cryptoStream = new CryptoStream(fsOut, encryptor, CryptoStreamMode.Write))
            {
                fsOut.Write(aesAlg.IV, 0, aesAlg.IV.Length);

                int bytesRead;
                byte[] buffer = new byte[4096];
                while ((bytesRead = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cryptoStream.Write(buffer, 0, bytesRead);
                }
            }
        }

        File.Delete(filePath);
    }

    static void DecryptFile(string encryptedFilePath, string password)
    {
        using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
        {
            aesAlg.Key = GetKey(password);

            using (FileStream fsIn = new FileStream(encryptedFilePath, FileMode.Open, FileAccess.Read))
            using (FileStream fsOut = new FileStream(Path.Combine(Path.GetDirectoryName(encryptedFilePath), Path.GetFileNameWithoutExtension(encryptedFilePath)), FileMode.Create, FileAccess.Write))
            {
                byte[] iv = new byte[aesAlg.BlockSize / 8];
                fsIn.Read(iv, 0, iv.Length);
                aesAlg.IV = iv;

                using (ICryptoTransform decryptor = aesAlg.CreateDecryptor())
                using (CryptoStream cryptoStream = new CryptoStream(fsIn, decryptor, CryptoStreamMode.Read))
                {
                    int bytesRead;
                    byte[] buffer = new byte[4096];
                    while ((bytesRead = cryptoStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        fsOut.Write(buffer, 0, bytesRead);
                    }
                }
            }
        }

        File.Delete(encryptedFilePath);
    }

    static void SaveKeyToFile(string filePath, string key)
    {
        File.WriteAllText(filePath, key);
    }

    static string GenerateRandomKey()
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        Random random = new Random();
        return new string(Enumerable.Repeat(chars, 32).Select(s => s[random.Next(s.Length)]).ToArray());
    }

    static byte[] GetKey(string password)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
        }
    }
}
