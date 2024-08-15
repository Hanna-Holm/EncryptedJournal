using Microsoft.AspNetCore.Identity;
using System.IO;
using System.Text.Json;

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
        private bool isLoggedIn = false;

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

            var hasher = new PasswordHasher<string>();
            string hashedPw = hasher.HashPassword(username, pw);

            if (hasAccount)
            {
                Login(pw, hasher);
            }
            else
            {
                CreateAccount(hashedPw);
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

        private void Login(string pw, PasswordHasher<string> hasher)
        {
            // Retrieve stored pw
            string fileAsText = File.ReadAllText(dbPath);
            Dictionary<string, string> KeyValuePairs = JsonSerializer.Deserialize<Dictionary<string, string>>(fileAsText);
            string storedPw = KeyValuePairs["password"];

            PasswordVerificationResult result = hasher.VerifyHashedPassword(username, storedPw, pw);
            Console.WriteLine(result);
        }

        private void CreateAccount(string hashedPw)
        {
            var keyValuePair = new Dictionary<string, string>
            {
                { "username", username },
                { "password", hashedPw },
                { "journal", "" }
            };

            string keyValue = JsonSerializer.Serialize(keyValuePair);
            File.WriteAllText(dbPath, keyValue);
        }

    }
}
