using System.Text;
using System.Threading.Tasks;
using Windows.Storage;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using System;
using System.IO;
using Windows.Storage.Streams;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Diagnostics;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace App7
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        private string sourceData;
        private int initialBufferSize = 1048576;
        public MainPage()
        {
            this.InitializeComponent();
        }

        private async void Button_Click(object sender, RoutedEventArgs e)
        {
            CreateSourceData();
            await CreateSourceFile();
            GC.Collect();
            await EncryptSourceFile("source.txt", "target.txt");
            await Decrypt("target.txt", "back.txt");
        }

        private async Task Decrypt(string sourceFile, string targetFile)
        {
            var target = await ApplicationData.Current.LocalFolder.CreateFileAsync(targetFile, Windows.Storage.CreationCollisionOption.ReplaceExisting);
            var source = await ApplicationData.Current.LocalFolder.GetFileAsync(sourceFile);
            var offSetFile = await ApplicationData.Current.LocalFolder.GetFileAsync(sourceFile+ "offsets");
            var offsets = await FileIO.ReadTextAsync(offSetFile);
            var encryptionOffsets = JsonConvert.DeserializeObject<List<int>>(offsets);
            using (var targetStream = await target.OpenStreamForWriteAsync())
            {
                using (var sourceInputStream = await source.OpenSequentialReadAsync())
                {
                    using (var sourceStream = sourceInputStream.AsStreamForRead())
                    {
                        foreach (var offset in encryptionOffsets)
                        {
                            var buffer = new byte[offset];
                            await sourceStream.ReadAsync(buffer, 0, buffer.Length);

                            var decrypted = DecryptTrack(buffer.AsBuffer());
                            var decryptedBuffer = decrypted.ToArray();
                            await targetStream.WriteAsync(decryptedBuffer, 0, decryptedBuffer.Length);
                        }

                    }
                }
            }
        }

        private async Task EncryptSourceFile(string sourceFile, string targetFile)
        {
            var encryptionOffsets = new List<int>();
            var bufferSize = initialBufferSize;
            var target = await ApplicationData.Current.LocalFolder.CreateFileAsync(targetFile, Windows.Storage.CreationCollisionOption.ReplaceExisting);
            var offSetFile = await ApplicationData.Current.LocalFolder.CreateFileAsync(targetFile+"offsets", Windows.Storage.CreationCollisionOption.ReplaceExisting);
            var source = await ApplicationData.Current.LocalFolder.GetFileAsync(sourceFile);
            using (var targetStream = await target.OpenStreamForWriteAsync())
            {
                using (var sourceInputStream = await source.OpenSequentialReadAsync())
                {
                    using (var sourceStream = sourceInputStream.AsStreamForRead())
                    {
                        var amountToRead = (int)sourceStream.Length;
                        var offset = 0;
                        while (offset < amountToRead)
                        {
                            if (offset + bufferSize >= amountToRead)
                            {
                                bufferSize = amountToRead - offset;
                            }

                            var buffer = new byte[bufferSize];
                            await sourceStream.ReadAsync(buffer, 0, bufferSize);
                            offset += bufferSize;

                            var encrypted = EncryptTrack(buffer.AsBuffer());
                            var encryptedBuffer = encrypted.ToArray();
                            encryptionOffsets.Add(encryptedBuffer.Length);
                            await targetStream.WriteAsync(encryptedBuffer, 0, encryptedBuffer.Length);
                        }
                    }
                }
            }

            var offsets = JsonConvert.SerializeObject(encryptionOffsets);
            await FileIO.WriteTextAsync(offSetFile, offsets);
        }

        private static IBuffer GetMD5Hash(string key)
        {
            // Convert the message string to binary data.
            IBuffer buffUtf8Msg = CryptographicBuffer.ConvertStringToBinary(key, BinaryStringEncoding.Utf8);

            // Create a HashAlgorithmProvider object.
            HashAlgorithmProvider objAlgProv = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Md5);

            // Hash the message.
            IBuffer buffHash = objAlgProv.HashData(buffUtf8Msg);

            // Verify that the hash length equals the length specified for the algorithm.
            if (buffHash.Length != objAlgProv.HashLength)
            {
                return null;
            }

            return buffHash;
        }

        public static IBuffer DecryptTrack(IBuffer toDecrypt)
        {

            // Get the MD5 key hash
            var keyHash = GetMD5Hash("P@ssw0rd");
            // Open a symmetric algorithm provider
            var aes = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
            // Create a symmetric key.
            var symetricKey = aes.CreateSymmetricKey(keyHash);
            // Decrypt Buffer
            return CryptographicEngine.Decrypt(symetricKey, toDecrypt, null);
        }

        public static IBuffer EncryptTrack(IBuffer toEncrypt)
        {

            // Get the MD5 key hash
            var keyHash = GetMD5Hash("P@ssw0rd");

            // Open a symmetric algorithm provider
            var aes = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);

            // Create a symmetric key.
            var symetricKey = aes.CreateSymmetricKey(keyHash);

            // Encrypt Buffer
            return CryptographicEngine.Encrypt(symetricKey, toEncrypt, null);
        }

        private void CreateSourceData()
        {
            var loopLength = 20;
            var rangeLength = 1024;
            var dataLength = 1024;
            var source = new StringBuilder(loopLength * rangeLength * dataLength);
            for (int loop = 0; loop < loopLength; loop++)
            {
                for (int range = 0; range < rangeLength; range++)
                {
                    for (int data = 0; data < dataLength; data++)
                    {
                        source.Append(loop + ":" + range);
                    }
                }
            }

            this.sourceData = source.ToString();
        }

        private async Task CreateSourceFile()
        {
            var source = await ApplicationData.Current.LocalFolder.CreateFileAsync("source.txt", Windows.Storage.CreationCollisionOption.ReplaceExisting);
            var stream = await source.OpenStreamForWriteAsync();
            using (var writer = new StreamWriter(stream))
            {
                await writer.WriteLineAsync(sourceData);
            }
        }
    }
}