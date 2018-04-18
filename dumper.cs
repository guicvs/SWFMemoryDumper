using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Diagnostics;
using System.Windows.Forms;
namespace TFMUpdater
{
    //Algoritmo desenvolvido por guicvs
    //https://github.com/guicvs
    internal class dumper
    {
        public Process[] processes;
        public guicvs_thequeen aobs = new guicvs_thequeen();
        public IntPtr[] addr_aob;
        public ProcessMemory hooked_process;
        public int maior = 0;

        public dumper(string processo_nome) 
        {
            try { processes = Process.GetProcessesByName(processo_nome); } catch (Exception ex) { return; } //tenta anexar o processo, caso falhar ele volta.
            addr_aob = aobs.ScanArray(processes[0], "46 57 53 ?? ?? ?? ?? 00 ?? 00 ?? ?? 00 00 ?? ?? 00 00 ?? 01 00 44 11 ?? 00 00 00 7F 13 ?? ?? ?? ?? 3C"); // anexar o address de todas as swf's no processo [46 57 53]  é o identificador para arquivos swf.
            hooked_process = new ProcessMemory(processes[0].Id); //cria um gancho que acessa a memoria do processo
            hooked_process.StartProcess(); // inicia o gancho
        }

        public void salvar_maior(string filename)
        {
            int adress_maior_swf = 0;
            foreach (int address in addr_aob)
            {
                
                try
                {
                    byte[] swf = hooked_process.ReadMem(address, 4);
                    byte[] swf2 = hooked_process.ReadMem(address + 4, 4);
                    string length_swf = "0x";

                    for (int x = swf2.Length - 1; x >= 0; x--)
                    {
                        
                            length_swf = length_swf + swf2[x].ToString("X");
                        
                    }

                    int len = Convert.ToInt32(length_swf, 16);
                    int address_final = address + len;

                    if (len > maior)
                    {
                        maior = len;
                        adress_maior_swf = address;
                    }
                    
                    
                    //
                }
                catch (Exception ex) { }


            }
            if(adress_maior_swf > 0)
            {
                File.WriteAllBytes(Application.StartupPath + "//aa" + filename + ".swf", hooked_process.ReadMem(adress_maior_swf, maior));
            }
            
        }

    }
}
