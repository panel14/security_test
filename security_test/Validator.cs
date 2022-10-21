using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace security_test
{
    //Класс для валидации данных 
    internal class Validator
    {
        //Проверка строки на пустоту
        public static string ValidateToEmpty()
        {
            string? password;
            //Если введенная строка пустая - просим ввести ещё раз
            while ((password = Console.ReadLine()) == string.Empty)
                Console.WriteLine("Value can not be empty.");
            return password;
        }

        //Верификация пароля
        public static bool VerifyPassword(string password, string hashedPassword)
        {
            //Хешируем введенный пароль
            string currentHash = Hasher.HashPassword(password);
            //Возвращаем соответствие введенного пароля и пароля из файла
            return  currentHash.Equals(hashedPassword);
        }
    }
}
