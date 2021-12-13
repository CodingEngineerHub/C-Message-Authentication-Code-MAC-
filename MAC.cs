using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace messageAuthenticationCode
{
    class MAC
    {
        public static byte[] getCC_MACNbytes(byte[] Kmac, byte[] eIFD, string Init_Vec)
        {



            // Split the 16 byte MAC key into two keys
            byte[] key1 = new byte[8];
            Array.Copy(Kmac, 0, key1, 0, 8);
            byte[] key2 = new byte[8];
            Array.Copy(Kmac, 8, key2, 0, 8);

            DES des1 = DES.Create();
            des1.BlockSize = 64;
            des1.Key = key1;
            des1.Mode = CipherMode.CBC;
            des1.Padding = PaddingMode.None;
            des1.IV = new byte[8];

            DES des2 = DES.Create();
            des2.BlockSize = 64;
            des2.Key = key2;
            des2.Mode = CipherMode.CBC;
            des2.Padding = PaddingMode.None;
            des2.IV = new byte[8];
            //des1 des2 key1 key2 

            // Padd the data with Padding Method 2 (Bit Padding)
            System.IO.MemoryStream out_Renamed = new System.IO.MemoryStream();
            //     Console.WriteLine(out_Renamed.Length);
            out_Renamed.Write(eIFD, 0, eIFD.Length);
            out_Renamed.WriteByte((byte)(0x80));
            //writes eifd and give last byte 0x80 
            while (out_Renamed.Length % 8 != 0)
            {
                out_Renamed.WriteByte((byte)0x00);
            }
            byte[] eIfd_padded = out_Renamed.ToArray();
            int N_bytes = eIfd_padded.Length / 8;  // Number of Bytes 

            byte[] d1 = new byte[8];
            byte[] dN = new byte[8];
            byte[] hN = new byte[8];
            byte[] intN = new byte[8];

            // MAC Algorithm 3
            // Initial Transformation 1
            //**************************Continue with this part ****************************
            Array.Copy(eIfd_padded, 0, d1, 0, 8);//d1 sets as first 8 element of data
            Console.WriteLine(" all data: " + Convert.ToHexString(eIfd_padded));
            Console.WriteLine(" des1 encryption starts:" + " \ndes1.Key:" + Convert.ToHexString(des1.Key) + " \ndes1.IV:" + Convert.ToHexString(des1.IV) + "\ndes1 Input:" + Convert.ToHexString(d1));
            hN = des1.CreateEncryptor().TransformFinalBlock(d1, 0, 8);

            Console.WriteLine(" des1 encryption result: " + Convert.ToHexString(hN));
            // Split the blocks
            // Iteration on the rest of blocks
            for (int j = 1; j < N_bytes; j++)
            {
                Array.Copy(eIfd_padded, (8 * j), dN, 0, 8);
                // XOR
                Console.WriteLine("xor operation strats\n" + "dn:" + Convert.ToHexString(dN));
                Console.WriteLine("hn: " + Convert.ToHexString(hN));
                for (int i = 0; i < 8; i++) //this for loop creates 8 byte xor operation 
                    intN[i] = (byte)(hN[i] ^ dN[i]);
                //dn is 8 block structure of all data and this valuye ğis shift for all operations
                Console.WriteLine("xor Results( intN[i] = (byte)(hN[i] ^ dN[i])): " + Convert.ToHexString(intN));

                // Encrypt
                hN = des1.CreateEncryptor().TransformFinalBlock(intN, 0, 8);
                Console.WriteLine(" des1 encryption starts:" + " \ndes1.Key:" + Convert.ToHexString(des1.Key) + " \ndes1.IV:" + Convert.ToHexString(des1.IV) + "\ndes1 Input:" + Convert.ToHexString(intN));
                Console.WriteLine(" des1 encryption result(hN): " + Convert.ToHexString(hN));

            }

            // Output Transformation 3
            //decrypt your last 8 byte data with using last enctyption results using des2 key

            //check Console.WriteLine(
            //in this you dont have to do padding
            byte[] hNdecrypt = des2.CreateDecryptor().TransformFinalBlock(hN, 0, 8);
            Console.WriteLine(" des2 Decryption starts:" + " \ndes2.Key:" + Convert.ToHexString(des2.Key) + " \ndes2.IV:" + Convert.ToHexString(des2.IV) + "\ndes2 Input:" + Convert.ToHexString(hN));
            Console.WriteLine(" des2 Decryption result(hNdecrypt): " + Convert.ToHexString(hNdecrypt));

            byte[] mIfd = des1.CreateEncryptor().TransformFinalBlock(hNdecrypt, 0, 8);
            //decrypted result encrypted by des1 key

            Console.WriteLine(" des1 encryption starts:" + " \ndes1.Key:" + Convert.ToHexString(des1.Key) + " \ndes1.IV:" + Convert.ToHexString(des1.IV) + "\ndes1 Input:" + Convert.ToHexString(hNdecrypt));
            Console.WriteLine(" des1 encryption result(hN): " + Convert.ToHexString(mIfd));



            //  Get check Sum CC
            Console.WriteLine(Convert.ToHexString(mIfd));

            return mIfd;
        }
    }
}
