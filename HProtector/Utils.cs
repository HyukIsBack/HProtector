using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace HProtector
{
    internal class Utils
    {
        static public byte[] GetKey()
        {
            using (RijndaelManaged myRijndael = new RijndaelManaged())
            {
                myRijndael.GenerateKey();

                return myRijndael.Key;
            }
        }

        static public byte[] GetIV()
        {
            using (RijndaelManaged myRijndael = new RijndaelManaged())
            {
                myRijndael.GenerateIV();

                return myRijndael.IV;
            }
        }
        static public string ToStringFromBytes(byte[] data = null)
        {
            if (data == null)
            {
                data = GetKey();
            }
            StringBuilder strb = new StringBuilder();
            for (int i = 0; i < data.Length - 1; i++)
            {
                strb.Append($"{data[i]}, ");
            }
            strb.Append(data[data.Length - 1]);  // 마지막 data 에는 ', ' 를 넣지말자.
            return strb.ToString();
        }
        static public byte[] HexStringToBytes(string hexData)
        {
            if (hexData == null)
            {
                return null;
            }

            List<byte> tempList = new List<byte>();

            // 2개씩 읽어들여서, 변환함.
            for (int i = 0; i < hexData.Length / 2; i++)
            {
                string hexValue = hexData.Substring(i * 2, 2);
                //Console.Write($"{hexValue}, ");
                tempList.Add(Convert.ToByte(hexValue, 16));  // 16진수 문자를, byte 로 변환.
            }

            return tempList.ToArray();
        }
        static public string ToHexStringFromBytes(byte[] data = null)
        {
            // **** 파일 or db 저장용. hex string 만들기 위함. ****
            // 반환값 형식 ex) 8B406FF18EE5AD0CD3AFFFD73F28B380B014D2420A0FC6C5BFCF40911CDB2E21

            if (data == null)
            {
                //data = GetKey();
                return null;
            }

            StringBuilder strb = new StringBuilder();

            for (int i = 0; i < data.Length; i++)
            {
                strb.Append($"{data[i]:X2}");  // 2자리 16진수로 변환.
            }

            return strb.ToString();
        }
        static public string GetEncryptedData(string data, byte[] Key, byte[] IV)
        {
            byte[] encData = EncryptStringToBytes(data, Key, IV); // **** 암호화된 data ****

            //===== encStr 을 파일이나, db 에 저장하여 사욯한다.  ===========
            // --- 저장하기 편하게 하기위해, 암호화된 byte[] 데이터 ==> hex string data로 변환.
            string encStr = Utils.ToHexStringFromBytes(encData);  // **** 파일 저장용. hex string ****

            return encStr;
        }

        static byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            byte[] encrypted;
            // Create an RijndaelManaged object
            // with the specified key and IV.
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }
    }
}
