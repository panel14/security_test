using System.Security.Cryptography;
using System.Text;

namespace security_test
{
    //Класс для хеширование пароля
    internal class Hasher
    {
        //Соль
        private static string salt = "Xas1h9==Az";
        //Функция хеширования
        public static string HashPassword(string password)
        {
            //Используется алгоритм SHA256
            var sha = SHA256.Create();
            byte[] bytesPassword = Encoding.Default.GetBytes(password);
            byte[] saltBytes = Encoding.Default.GetBytes(salt);

            byte[] allBytes = bytesPassword.Concat(saltBytes).ToArray();

            byte[] hash = sha.ComputeHash(allBytes);

            return Convert.ToBase64String(hash);
        }
    }
}
