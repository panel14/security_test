using System.Security.AccessControl;
using System.Security.Principal;

namespace security_test
{
    //Класс для зашиты файлов
    internal class FileProtector
    {
        //Идентификатор текущего пользователя
        private static readonly SecurityIdentifier user = WindowsIdentity.GetCurrent().User;
        private static bool rootCreate = false;

        //Функция, добавляет новые права на файл текущему пользователю
        public static void AddFileSecurity(string filename, List<FileSystemRights> rights)
        {
            //Получаем объект fileInfo - всю информацию о файле
            var fileInfo = new FileInfo(filename);
            //Получаем объект fileSecurity - список прав и аудитов для файла (ACL)
            FileSecurity fileSecurity = fileInfo.GetAccessControl();

            foreach(FileSystemRights right in rights)
            {
                //Добавляем новые права для файла, причём ControlType - Deny, т.е. запрещаем доступ к правам (модификации, удаления и тд)
                fileSecurity.AddAccessRule(new FileSystemAccessRule(user, right, AccessControlType.Deny));
            }
            //Активируем созданный выше набор правил
            fileInfo.SetAccessControl(fileSecurity);
        }

        //Функция обратная AddFileSecurity - работает абсолютно аналогично, только права ограничения доступа удаляются у файла - защита снимается
        public static void RemoveFileSecurity(string filename, List<FileSystemRights> rights)
        {
            var fileInfo = new FileInfo(filename);
            FileSecurity fileSecurity = fileInfo.GetAccessControl();

            foreach (FileSystemRights right in rights)
            {
                fileSecurity.RemoveAccessRule(new FileSystemAccessRule(user, right, AccessControlType.Deny));
            }
            fileInfo.SetAccessControl(fileSecurity);
        }

        //Функция наблюдения за директорией и файлами (шаблонами)
        public static void WatchFromDirectory(List<string> templates, ref List<FileSystemWatcher> watchers, ref List<FileStream> streams)
        {
            //Инициализируем наблюдателя, для каждого шаблона. Наблюдатели отслеживают события файлов (создание, перенаименование и тд) и
            //обрабатывают эти события
            foreach (string template in templates)
            {
                //Создаём наблюдателя
                FileSystemWatcher watcher = new(Environment.CurrentDirectory);
                //Добавляем флаги для событий
                watcher.NotifyFilter = NotifyFilters.Attributes
                        | NotifyFilters.CreationTime
                        | NotifyFilters.FileName
                        | NotifyFilters.LastAccess
                        | NotifyFilters.FileName
                        | NotifyFilters.DirectoryName;
                //Добавляем события, которые будут происходить при изменениях файлов/директории
                watcher.Created += OnCreated;
                watcher.Renamed += OnRenamed;
                //Добавляем шаблон
                watcher.Filter = template;

                watcher.IncludeSubdirectories = true;
                watcher.EnableRaisingEvents = true;
                watchers.Add(watcher);

                //Открываем потоки файлами шаблонов (если они созданы) - нужно для отключения возможности удаления, перемещения
                if (File.Exists(template))
                {
                    var fs = File.Open(template, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    streams.Add(fs);
                }
            }
            

        }
        //Функция обработчика создания файла - создание запрещено, поэтому файл-шаблон сразу же удаляется
        private static void OnCreated(object sender, FileSystemEventArgs e)
        {
            if (!rootCreate)
            {
                FileSystemWatcher watcher = (FileSystemWatcher)sender;
                string template = watcher.Filter;
                //Если файл был создан - удаляем
                File.Delete(template);
                Console.WriteLine($"Creation of file {template} denied.");
            }
            rootCreate = false;
        }
        //Функция обработчика перенаименования файла - перенаменование запрещено, поэтому файлу возвращается старое название
        private static void OnRenamed(object sender, FileSystemEventArgs e)
        {
            FileSystemWatcher watcher = (FileSystemWatcher)sender;
            string template = watcher.Filter;
            //Если файл был назван своим именем -> он был только что создан, вызываем событие при создании
            if (e.Name.Equals(template))
            {
                OnCreated(sender, e);
            }
            else
            {                
                rootCreate = true;
                //Иначе, копируем содержимое переименованного файла в файл с именем шаблона
                File.Copy(e.Name, template, true);
                //переименованный файл удаляем
                File.Delete(e.Name);
                Console.WriteLine($"Renaming of file {template} denied.");
            }
        }

        //Очищаем ресурсы - удаляем из памяти наблюдателей и потоки файлов
        public static void Clean(ref List<FileSystemWatcher> watchers, ref List<FileStream> streams)
        {
            for (int i = 0; i < watchers.Count; i++)
            {
                watchers[i].Dispose();
                if (streams.Count > i)
                {
                    streams[i].Close();
                    streams[i].Dispose();
                }
            }
        }
    }   
}
