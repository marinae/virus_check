using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.IO;
using System.Text.RegularExpressions;

namespace VirusCheck
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            textBox1.Text = @"C:\Test\Source\";
            textBox2.Text = @"C:\Test\Result\";
        }

        private void button3_Click(object sender, EventArgs e)
        {
            string dSource = textBox1.Text;
            string dResult = textBox2.Text;

            DirectoryInfo diSource = new DirectoryInfo(dSource);
            DirectoryInfo diResult = new DirectoryInfo(dResult);            

            if (diSource.Exists && diResult.Exists)
            {
                int fileCount = diSource.GetFiles("*.csv", SearchOption.TopDirectoryOnly).Length;
                string[] filePaths = Directory.GetFiles(dSource);
                string line;
                string hash;
                string fileName;
                string fileSize;
                string isVirus;
                string tmp;
                string userID;
                string hashString = ""; // запишем все встретившиеся hash
                string hashStringTotal = "";

                System.IO.StreamWriter sw = new StreamWriter(dResult + "ScanReport.csv");
                System.IO.StreamWriter swTotal = new StreamWriter(dResult + "TotalReport.csv");                

                for (int i = 0; i < fileCount; i++)
                {
                    System.IO.StreamReader file = new StreamReader(filePaths[i]);

                    while ((line = file.ReadLine()) != null)
                    {
                        // вырезаем Hash и запоминаем
                        int index = line.IndexOf(";");
                        hash = line.Substring(0, index);
                        line = line.Substring(index + 1);
                        if (!hashString.Contains(hash))
                            hashString += hash + ";";
                        hashStringTotal += hash + ";";

                        // вырезаем FileName
                        index = line.IndexOf(";");
                        fileName = line.Substring(0, index);
                        line = line.Substring(index + 1);

                        // вырезаем FileSize
                        index = line.IndexOf(";");
                        fileSize = line.Substring(0, index);
                        line = line.Substring(index + 1);

                        // вырезаем IsVirus
                        isVirus = line.Substring(0, 1);                        

                        // присваиваем UserID
                        tmp = filePaths[i].Substring(0);
                        while ((index = tmp.IndexOf(@"\")) != -1)
                            tmp = tmp.Substring(index + 1);
                        userID = tmp.Substring(0, 5);

                        // записываем результат в файл ScanReport.csv
                        sw.WriteLine(userID + ";" + fileName + ";" + isVirus + ";" + hash + ";" + fileSize);
                    }

                    hashStringTotal += "|"; // признак конца одного файла
                    file.Close();
                }

                // записываем результат в файл TotalReport.csv
                int amountFiles;
                int amountTotal;                
                tmp = "";

                // для каждого hash ищем вхождения - UserCount и FileCount
                while (hashString.Length > 0)
                {
                    string tmp_hashStringTotal = hashStringTotal.Substring(0);
                    int indexHash = hashString.IndexOf(";");
                    hash = hashString.Substring(0, indexHash);
                    hashString = hashString.Substring(indexHash + 1);
                    amountTotal = new Regex(hash).Matches(hashStringTotal).Count;
                    amountFiles = 0;

                    while (tmp_hashStringTotal.Length > 0)
                    {
                        int index = tmp_hashStringTotal.IndexOf("|");
                        tmp = tmp_hashStringTotal.Substring(0, index);
                        if (tmp.Contains(hash))
                            amountFiles++;
                        tmp_hashStringTotal = tmp_hashStringTotal.Substring(index + 1);
                    }

                    // результат
                    swTotal.WriteLine(hash + ";" + amountFiles.ToString() + ";" + amountTotal.ToString());
                }

                sw.Close();
                swTotal.Close();
                MessageBox.Show("Успешно", "Результат", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
                MessageBox.Show("Неверный путь", "Результат", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
