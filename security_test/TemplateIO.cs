using System.Security.AccessControl;

namespace security_test
{
    //Класс для работы (чтение / запись) с файлом template.tbl
    internal class TemplateIO
    {
        //Имя файла в текущей директории
        private static readonly string FILENAME = $"{Environment.CurrentDirectory}\\template.tbl";
        //Права доступа к файлу template.tbl
        private static readonly List<FileSystemRights> rights = new() { FileSystemRights.Modify, FileSystemRights.Read, FileSystemRights.Delete };

        //Функция для создания файла
        private static void CreateFile()
        {
            Console.WriteLine("Template file does not exist. It'll be created, input password for access to secure functions:");
            var sw = File.AppendText(FILENAME);
            //Принимаем пароль от юзера
            string password = Validator.ValidateToEmpty();
            //Записываем пароль в файл в хешированном виде
            sw.WriteLine(Hasher.HashPassword(password));

            Console.WriteLine("Template created, password saved");
            //Ставим защиту на файл
            FileProtector.AddFileSecurity(FILENAME, rights);
            sw.Close();
        }
        //Проверка корректности пароля
        public static bool ReadAccess()
        {
            //Снимаем защиту с файла
            FileProtector.RemoveFileSecurity(FILENAME, rights);

            Console.WriteLine("Password:");
            string password = Validator.ValidateToEmpty();
            //Читаем пароль с файла
            using var sr = new StreamReader(FILENAME);
            string hash = sr.ReadLine();
            //Ставим защиту обратно
            FileProtector.AddFileSecurity(FILENAME, rights);

            //Проверяем пароль на соотвествие
            if (!Validator.VerifyPassword(password, hash))
                return false;
            return true;
        }
        //Считывание шаблонов с файла
        public static bool ReadTemplate(ref List<string> templates)
        {
            //Чистим лист при каждом чтении (т.к. лист - глобальная переменная)
            if (templates.Count > 0) templates.Clear();
            if (!File.Exists(FILENAME)) CreateFile();
            //Снимаем защиту с файла
            FileProtector.RemoveFileSecurity(FILENAME, rights);
            
            using var sr = new StreamReader(FILENAME);
            //Читаем содержимое файла и приобразвываем к листу
            templates = sr.ReadToEnd().Trim().Split("\r\n").ToList();
            sr.Close();
            sr.Dispose();
            //Ставим защиту обратно
            FileProtector.AddFileSecurity(FILENAME, rights);
            return true;
        }
        //Запись нового шаблона в файл
        public static bool WriteTemplate(string template)
        {
            if (!File.Exists(FILENAME)) CreateFile();
            //Если пароль неверный, прекращаем выполнение
            if (!ReadAccess()) return false;
            //Снимаем защиту с файла
            FileProtector.RemoveFileSecurity(FILENAME, rights);
            //Иначе - добавляем новый шаблон в файл
            File.AppendAllLines(FILENAME, new List<string> { template });
            //Ставим защиту обратно
            FileProtector.AddFileSecurity(FILENAME, rights);

            return true;
        }
        //Удаление шаблона из файла
        public static void DeleteTemplate(string template)           
        {
            if (!File.Exists(FILENAME)) CreateFile();
            //Снимаем защиту с файла
            FileProtector.RemoveFileSecurity(FILENAME, rights);

            var sr = new StreamReader(FILENAME);
            //Читаем содержимое файла и преобразовываем к листу
            List<string> templates = sr.ReadToEnd().Trim().Split("\r\n").ToList();
            //Удаляем шаблон
            templates.Remove(template);
            //Корректно закрываем поток чтения
            sr.Close();
            sr.Dispose();

            //Переписываем файл, добавляем все шаблоны, кроме удаленного
            File.WriteAllLines(FILENAME, templates);

            //Ставим защиту обратно
            FileProtector.AddFileSecurity(FILENAME, rights);
        }
    }
}
