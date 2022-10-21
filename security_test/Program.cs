using security_test;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

const int MF_BYCOMMAND = 0x00000000;
const int SC_CLOSE = 0xF060;
//Импорт библиотек для отключения кнопки закрытия окна приложения
[DllImport("user32.dll")]
static extern int DeleteMenu(IntPtr hMenu, int nPosition, int wFlags);

[DllImport("user32.dll")]
static extern IntPtr GetSystemMenu(IntPtr hWnd, bool bRevert);

[DllImport("kernel32.dll", ExactSpelling = true)]
static extern IntPtr GetConsoleWindow();

//Отключение кнопки закрытия окна приложения
DeleteMenu(GetSystemMenu(GetConsoleWindow(), false), SC_CLOSE, MF_BYCOMMAND);

Console.WriteLine("Input command:\n" +
    "s - protect all files from templates.tbl\n" +
    "a - add new template at template.tbl\n" +
    "d - delete template from temaplate.tbl\n" +
    "sh - show template.tbl\n" +
    "e - exit");
//Права для template.tbl - создание, удаление и редактирование.
List<FileSystemRights> rights = new() { FileSystemRights.CreateFiles, FileSystemRights.Delete, FileSystemRights.Modify };
List<string> templates = new();

while (true)
{
    Console.WriteLine("Command:");
    switch (_ = Console.ReadLine())
    {
        //Команда активации защищенного режима
        case "s":
            //Если удалось прочитать шаблоны с файла
            if (TemplateIO.ReadTemplate(ref templates))
            {
                //Удаляем первую строку - хешированный пароль
                templates.RemoveAt(0);
                Console.WriteLine("Files protected in real time.");
                List<FileSystemWatcher> watchers = new();
                List<FileStream> openedStreams = new();
                //Запуск функции защиты файлов
                FileProtector.WatchFromDirectory(templates, ref watchers, ref openedStreams);

                Console.WriteLine("Press password to leave security mode.");
                //Для отключения необходимо ввести пароль
                while (!TemplateIO.ReadAccess()) Console.WriteLine("Wrong password. Try again.");
                //После успешного ввода чистим все занятые защитой ресурсы
                FileProtector.Clean(ref watchers, ref openedStreams);
                watchers.Clear();
                openedStreams.Clear();
            }
            else
            {
                Console.WriteLine("Access denied. Incorrect password.");
            }

            break;

        //Команда для добавления нового шаблона в файл
        case "a":
            Console.WriteLine("Input new template with extension:");
            //Проверка строки на пустоту
            string template = Validator.ValidateToEmpty();
            //Если удалось записать шаблон в файл
            if (TemplateIO.WriteTemplate(template))
                Console.WriteLine("Template created.");
            else
                Console.WriteLine("Access denied. Incorrect password.");

            break;
        //Команда удаления шаблона из файла
        case "d":
            //Если пароль неверный
            if (!TemplateIO.ReadAccess())
            {
                Console.WriteLine("Wrong password, access denied.");
            }
            //Если пароль подходит
            else
            {
                Console.WriteLine("Input template to delete:");
                string temp = Validator.ValidateToEmpty();
                //Удаляем шаблон из файла
                TemplateIO.DeleteTemplate(temp);
                Console.WriteLine("Template deleted.");
            }

            break;
        //Команда для показа содержимого файла
        case "sh":
            //Если пароль не подходит
            if (!TemplateIO.ReadAccess()) 
            {
                Console.WriteLine("Wrong password, access denied.");
            } 
            else
            {
                //Если подходит, то выводим все шаблоны на экран
                if (TemplateIO.ReadTemplate(ref templates))
                {
                    templates.ForEach(x => Console.WriteLine(x));
                }
            }
            break;
        //Команда закрытия приложения
        case "e":
            Console.WriteLine("Shut down");
            return;
        default:
            Console.WriteLine("Unknown command");
            break;
    }
}



