using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.IO;
using System.Text.Json;
using System.Drawing;
using System.Security.Cryptography;
using System.Collections.Generic;

namespace EncryptedJournal
{
    internal class JournalApp
    {
        private string welcomeMsg = "Welcome to the Encrypted Journal App!";
        private string loginChoice = "1";
        private string createAccountChoice = "2";
        private bool hasAccount;
        public string username { get; private set; }
        private string dbPath = "db.json";
        private byte[] key;
        private bool isLoggedIn = false;
        private PasswordHasher<string> hasher = new PasswordHasher<string>();

        public JournalApp()
        {
            Console.WriteLine(welcomeMsg);
        }

        public void Start() 
        {
            ChoosePath();
        }

        private void ChoosePath()
        {
            bool validChoice = false;
            while (!validChoice)
            {
                string choice = GetChoiceFromUser();

                if (choice == loginChoice || choice == createAccountChoice)
                {
                    validChoice = true;

                    if (choice == loginChoice)
                    {
                        hasAccount = true;
                    }
                    EnterCredentials();
                }
                else
                    Console.WriteLine("Please press either 1 or 2.");
            }
        }

        private string GetChoiceFromUser()
        {
            Console.WriteLine("Do you want to log in or create a new account? Press 1 or 2 depending on your choice.");
            Console.WriteLine("1. Log in \n2. Create new account");
            return Console.ReadLine();
        }

        private void EnterCredentials()
        {
            Console.Write("Username: ");
            username = GetUserInput();
            Console.Write("Password: ");
            string pw = GetUserInput();

            string hashedPw = hasher.HashPassword(username, pw);

            if (hasAccount)
            {
                Login(pw);
            }
            else
            {
                CreateAccount(pw, hashedPw);
            }
        }
        private string GetUserInput()
        {
            bool isValid = false;

            while (!isValid)
            {
                string input = Console.ReadLine();

                if (input != "")
                {
                    return input;
                }
                else
                {
                    Console.WriteLine("Invalid input. Try again.");
                }
            }

            return null;
        }

        private void Login(string pw)
        {
            string storedPw = GetValueFromKey("password");
            string storedSaltAsText = GetValueFromKey("salt");
            byte[] salt = Convert.FromBase64String(storedSaltAsText);
            if (TryAuthenticate(pw, storedPw))
            {
                isLoggedIn = true;
                DeriveKey(pw, salt);
                string journal = DecryptJournal();
            }
        }

        private void DeriveKey(string pw, byte[] salt)
        {
            key = KeyDerivation.Pbkdf2(pw, salt, KeyDerivationPrf.HMACSHA256, 100000, 32);
        }
        
        private string DecryptJournal()
        {
            throw new NotImplementedException();
        }

        private string GetValueFromKey(string key)
        {
            string fileAsText = File.ReadAllText(dbPath);
            Dictionary<string, string> KeyValuePairs = JsonSerializer.Deserialize<Dictionary<string, string>>(fileAsText);
            return KeyValuePairs[key];
        }

        private bool TryAuthenticate(string pw, string storedPw)
        {
            return hasher.VerifyHashedPassword(username, storedPw, pw) == PasswordVerificationResult.Success ? true : false;
        }

        private void CreateAccount(string pw, string hashedPw)
        {
            byte[] salt = GenerateSalt();
            
            string journalText = "";

            EncryptAndSaveToFile(pw, hashedPw, salt, journalText);
        }

        private void EncryptAndSaveToFile(string password, string hashedPw, byte[] salt, string textToEncrypt)
        {
            key = KeyDerivation.Pbkdf2(password, salt, KeyDerivationPrf.HMACSHA256, 100000, 32);
            byte[] encryptedJournal = EncryptText(key, textToEncrypt);
            string encryptedJournalAsText = Convert.ToBase64String(encryptedJournal);
            string saltString = Convert.ToBase64String(salt);

            var keyValuePair = new Dictionary<string, string>
            {
                { "username", username },
                { "password", hashedPw },
                { "salt", saltString },
                { "journal", encryptedJournalAsText }
            };

            string dbAsText = JsonSerializer.Serialize(keyValuePair);
            File.WriteAllText(dbPath, dbAsText);
        }

        private byte[] GenerateSalt()
        {
            byte[] salt = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            return salt;
        }

        private byte[] EncryptText(byte[] key, string plainText)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.GenerateIV();

                using (MemoryStream ms = new MemoryStream())
                {
                    ms.Write(aes.IV, 0, aes.IV.Length);

                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(plainText);
                    }

                    return ms.ToArray();
                }
            }
        }
    }
}
