using System;

namespace messageAuthenticationCode
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] Kenc = Convert.FromHexString("AB94FDECF2674FDFB9B391F85D7F76F2");
            byte[] Kmac = Convert.FromHexString("7962D9ECE03D1ACD4C76089DCE131543");
            byte[] eIFD = Convert.FromHexString("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2");
            string Init_Vec = "0000000000000000";
            MAC.getCC_MACNbytes(Kmac, eIFD, Init_Vec);
        }
    }
}
