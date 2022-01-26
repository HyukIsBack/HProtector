using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HProtector
{
    internal class Engine
    {
		private static string randomChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
		private static Random rand = new Random();
		public static string GenerateRandomString(int length)
		{
			string text = "";
			for (int i = 0; i < length; i++)
			{
				text += Engine.randomChars[Engine.rand.Next(0, Engine.randomChars.Length)].ToString();
			}
			return text;
		}
	}
}
