//****************************** MHLibrary *******************************
//************************************************************************
//************************* NO RELEASE ALLOWED !**************************
//************************************************************************
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Collections;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;
using System.IO;
using System.Security.Cryptography;

namespace hibProcesses
{

    /// <summary>
    /// SecurityMgr
    /// </summary>
    public class SecurityMgr
    {
        //---------------------------------------
        //--------------- Global ----------------
        /// <summary>
        /// Close application properly.
        /// </summary>
        private class CloseApp
        {
        }


        //---------------------------------------
        //------------ Types/Forms --------------
        /// <summary>
        /// Crypt types with a TripleDES key into the memory.
        /// </summary>
        public static class MemoryProtector
        {
            //----------------------------
            //----------- Base -----------

            /// <summary>
            /// ProtectedType
            /// </summary>
            public class ProtectedType
            {
                //-------------------------
                //-------- Defines --------

                /// <summary>
                /// TDES Data
                /// </summary>
                private byte[] mData;

                /// <summary>
                /// Triple DES Key
                /// </summary>
                private byte[] mTDESKey;

                //-------------------
                //------ Voids ------

                /// <summary>
                /// Set_Bytes
                /// </summary>
                public bool Set_Bytes(byte[] OriginalData)
                {
                    //Call Crypt()
                    return Crypt(OriginalData);
                }

                /// <summary>
                /// Crypt
                /// </summary>
                private bool Crypt(byte[] OriginalData)
                {
                    try
                    {
                        //------------------------------------
                        //---Generate Triple DES StaticKey----
                        //New UTF8 Object
                        System.Text.UTF8Encoding UTF8 = new System.Text.UTF8Encoding();

                        //New Md5 Object
                        MD5CryptoServiceProvider HashProvider = new MD5CryptoServiceProvider();

                        //Generate new static TDESKey
                        mTDESKey = HashProvider.ComputeHash(UTF8.GetBytes(Randomizer.GenRandomString()));


                        //------------------------------------
                        //----------------Crypt----------------
                        //Create New TDES Object
                        TripleDESCryptoServiceProvider TDESAlgorithm = new TripleDESCryptoServiceProvider();

                        //Setup
                        TDESAlgorithm.Key = mTDESKey;
                        TDESAlgorithm.Mode = CipherMode.ECB;
                        TDESAlgorithm.Padding = PaddingMode.PKCS7;

                        //Crypt
                        try
                        {
                            ICryptoTransform Encryptor = TDESAlgorithm.CreateEncryptor();
                            mData = Encryptor.TransformFinalBlock(OriginalData, 0, OriginalData.Length);
                            Encryptor.Dispose();
                            Encryptor = null;
                        }
                        finally
                        {
                            TDESAlgorithm.Clear();
                        }

                        //Dispose
                        TDESAlgorithm = null;
                        UTF8 = null;
                        HashProvider = null;

                        //Return
                        return true;
                    }
                    catch
                    {
                        new CloseApp();
                        return false;
                    }
                }

                /// <summary>
                /// Get_Bytes
                /// </summary>
                public byte[] Get_Bytes()
                {
                    //Call Decrypt()
                    return DeCrypt();
                }

                /// <summary>
                /// DeCrypt
                /// </summary>
                private byte[] DeCrypt()
                {
                    try
                    {
                        //Create New TDES Object
                        TripleDESCryptoServiceProvider TDESAlgorithm = new TripleDESCryptoServiceProvider();

                        //Setup
                        TDESAlgorithm.Key = mTDESKey;
                        TDESAlgorithm.Mode = CipherMode.ECB;
                        TDESAlgorithm.Padding = PaddingMode.PKCS7;

                        //DeCrypt
                        byte[] Result;
                        try
                        {
                            ICryptoTransform Decryptor = TDESAlgorithm.CreateDecryptor();
                            Result = Decryptor.TransformFinalBlock(mData, 0, mData.Length);
                            Decryptor.Dispose();
                            Decryptor = null;
                        }
                        finally
                        {
                            TDESAlgorithm.Clear();
                        }

                        //Dispose
                        TDESAlgorithm = null;

                        //Return
                        return Result;
                    }
                    catch
                    {
                        new CloseApp();
                        return null;
                    }
                }

            }

            //----------------------------
            //-------- SubClasses --------

            /// <summary>
            /// Protected_Bytes
            /// </summary>
            public class Protected_Bytes : ProtectedType
            {
                /// <summary>
                /// Constructor
                /// </summary>
                public Protected_Bytes(byte[] OriginalBytes)
                {
                    Set_Bytes(OriginalBytes);
                }
            }

            /// <summary>
            /// Protected_String
            /// </summary>
            public class Protected_String : ProtectedType
            {
                /// <summary>
                /// Constructor
                /// </summary>
                public Protected_String(string OriginalString)
                {
                    Set_String(OriginalString);
                }

                /// <summary>
                /// Get_String
                /// </summary>
                public string Get_String()
                {
                    //New UTF8 Object
                    System.Text.UTF8Encoding EUTF8 = new System.Text.UTF8Encoding();

                    //Return
                    return EUTF8.GetString(Get_Bytes());
                }

                /// <summary>
                /// Set_String
                /// </summary>
                public bool Set_String(string OriginalString)
                {
                    //New UTF8 Object
                    System.Text.UTF8Encoding EUTF8 = new System.Text.UTF8Encoding();

                    //Return
                    return Set_Bytes(EUTF8.GetBytes(OriginalString));
                }

            }

        }

        /// <summary>
        /// Secure a form.
        /// </summary>
        public static class SecureForm
        {
            /// <summary>
            /// Set default security properties on a form
            /// </summary>
            /// <param name="Form">Form to protect</param>
            public static void Properties(Form Form)
            {
                //Set Basic Property
                Form.MinimizeBox = false;
                Form.MaximizeBox = false;

                //Set Random Name
                Form.Text = Randomizer.GenRandomString();
            }


        }


        //---------------------------------------
        //----- Debugger/Hook/Scanner/Crack -----
        /// <summary>
        /// Search into each Windows/Processes a not authorized tool.
        /// </summary>
        private class AntiScanner
        {

            //-----------------
            //----- Enums -----

            /// <summary>
            /// Available actions when a Scanner was find.
            /// </summary>
            private enum eOnFound : uint
            {
                /// <summary>
                /// Close own Application
                /// </summary>
                CloseOwnApplication = 0x00000010,
                /// <summary>
                /// Close target Application
                /// </summary>
                CloseTargetApplication = 0x00000020,
                /// <summary>
                /// Write chit to generate a bug
                /// </summary>
                WriteChit = 0x00000040,
                /// <summary>
                /// Reset all Patterns
                /// </summary>
                ResetAllPatterns = 0x00000100,
            }

            //--------------------
            //----- Settings -----

            /// <summary>
            /// Actual AntiScanner
            /// </summary>
            private static AntiScanner mAntiScanner = null;

            /// <summary>
            /// Action when a Scanner was find.
            /// </summary>
            private eOnFound OnFound = eOnFound.CloseOwnApplication;


            //--------------------
            //------ Lists -------
            /// <summary>
            /// Black list of usual Scanners Process's Name
            /// </summary>
            private List<MemoryProtector.Protected_String> BlackListedProcess = new List<MemoryProtector.Protected_String>();

            /// <summary>
            /// Black list of usual Scanners Window's Names
            /// </summary>
            private List<MemoryProtector.Protected_String> BlackListedWindows = new List<MemoryProtector.Protected_String>();


            //----------------------------
            //-- Constructor/Initialize --

            /// <summary>
            /// Constructor
            /// </summary>
            public AntiScanner()
            {
                //Initialyze Content
                InitializeContent();

                //Start GlobalThread
                new Thread(new ThreadStart(GlobalThread)).Start();
            }

            /// <summary>
            /// Create void
            /// </summary>
            public static bool Initialize()
            {
                //Check if a AntiScanner is already created
                if (mAntiScanner == null)
                {
                    //Create new AntiScanner
                    mAntiScanner = new AntiScanner();

                    //Return true
                    return true;
                }
                else
                {
                    //Return false
                    return false;
                }
            }


            //------------------
            //---- Scanners ----

            /// <summary>
            /// Initialyze the content of each BlackList
            /// </summary>
            private void InitializeContent()
            {
                try
                {
                    #region CheatEngine

                    //Process and Windows Name
                    BlackListedProcess.Add(new MemoryProtector.Protected_String("cheatengine-i386"));
                    BlackListedProcess.Add(new MemoryProtector.Protected_String("cheatengine-x86_64"));
                    BlackListedProcess.Add(new MemoryProtector.Protected_String("Cheat Engine"));
                    BlackListedWindows.Add(new MemoryProtector.Protected_String("Art Money"));
                    BlackListedWindows.Add(new MemoryProtector.Protected_String("Cheat Engine"));

                    #endregion CheatEngine
                    #region ArtMoney

                    //Process and Windows Name
                    BlackListedWindows.Add(new MemoryProtector.Protected_String("ArtMoney"));

                    #endregion ArtMoney
                    #region OllyDBG

                    //Process and Windows Name
                    BlackListedWindows.Add(new MemoryProtector.Protected_String("OllyDbg"));

                    #endregion OllyDBG
                }
                catch
                {
                    new CloseApp();
                }
            }

            /// <summary>
            /// Check for process's name list
            /// </summary>
            private void ScanProcessName()
            {
                try
                {
                    //Get All Process
                    Process[] pArray = Process.GetProcesses();

                    //Check
                    foreach (Process p in pArray)
                    {
                        foreach (MemoryProtector.Protected_String s in BlackListedProcess)
                        {
                            if (p.ProcessName == s.Get_String())
                            {
                                //Found
                                Found(p.Id);
                            }
                        }
                    }

                    //Dispose
                    pArray = null;
                }
                catch
                {
                    new CloseApp();
                }
            }

            /// <summary>
            /// Check for window's name list
            /// </summary>
            private void ScanWindowsName()
            {
                try
                {
                    //Check with FindWindows
                    foreach (MemoryProtector.Protected_String Wd in BlackListedWindows)
                    {
                        IntPtr Handle = WindowsMgr.FindMainWindow(null, Wd.Get_String());
                        if (Handle != IntPtr.Zero)
                        {
                            //Found
                            Found(hibProcess.GetProcessIdFromWindow(Handle));
                        }
                        Handle = IntPtr.Zero;
                    }
                }
                catch
                {
                    new CloseApp();
                }
            }

            /// <summary>
            /// Found
            /// </summary>
            private void Found(int PID)
            {
                try
                {
                    if (OnFound == eOnFound.CloseOwnApplication)
                    {
                        foreach (Form form in Application.OpenForms)
                        {
                            form.Close();
                        }
                    }
                }
                catch
                {
                    new CloseApp();
                }
            }


            //------------------
            //---- Threads -----

            /// <summary>
            /// GlobalThread
            /// </summary>
            void GlobalThread()
            {
                try
                {

                    //Define SmallCheck
                    int CheckLoop = 1;

                    //Check OpenForms
                    while (Application.OpenForms.Count != 0)
                    {
                        while (Application.OpenForms.Count != 0)
                        {
                            //CheckScan Type
                            if (CheckLoop < 10)
                            {
                                //Scan Process's name
                                ScanProcessName();

                                //Scan Windows's name
                                ScanWindowsName();

                                //Increase CheckLoop
                                CheckLoop += 1;
                            }
                            else
                            {
                                //Scan Process's name
                                ScanProcessName();

                                //Scan Process's memory
                                //ScanProcessMemory();

                                //Scan Windows's name
                                ScanWindowsName();

                                //Reset CheckLoop
                                CheckLoop = 0;
                            }

                            //Sleep
                            Thread.Sleep(5000);
                        }
                        Thread.Sleep(1000);
                    }
                }
                catch
                {
                    new CloseApp();
                }
            }

        }


        //---------------------------------------
        //------------ Randomizer ---------------
        /// <summary>
        /// Class to generate randoms things , like strings, char , int ....
        /// </summary>
        public static class Randomizer
        {
            /// <summary>
            /// Get a random String.
            /// </summary>
            public static string GenRandomString()
            {
                System.Random Random = new System.Random();
                int Size = Random.Next(5, 20);
                string AleatoryString = "";
                for (int i = 1; i <= Size; i++)
                {
                    if (Random.Next(0, 3) == 1)
                    {
                        AleatoryString = AleatoryString + (char)Random.Next(0x61, 0x7A);
                    }
                    else
                    {
                        AleatoryString = AleatoryString + Random.Next(0,10);
                    }
                }
                return AleatoryString;
            }


        }


        //---------------------------------------
        //----------- Defines/Voids -------------
        /// <summary>
        /// Initialyze the security manager.
        /// </summary>
        public static void Initialize()
        {
            //Initialize AntiScanner
            AntiScanner.Initialize();
        }


    }


}
