using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Graphics.Imaging;
using Windows.Storage;
using Windows.Storage.Streams;

namespace BrokeredComponent1
{
    public sealed class FileGenerator
    {

        private const String APP_DATA_PACKAGES_PATH = @"C:\Users\ranbi\AppData\Local\Packages";

        private const String CORTANA_PATH_PREFIX = @"Microsoft.Windows.Cortana";

        private const int PHOTO_MAX_SIZE = 640;

        public void LaunchUri(String uri)
        {
            Process.Start(uri);
        }

        public IAsyncOperation<StorageFile> GenerateTemparoryFileForCortana(String filePath)
        {
            return Task.Run<StorageFile>(async () =>
            {
                //Resize the source file to buffer.
                Windows.Storage.Streams.Buffer buffer = null;
                StorageFile file = await StorageFile.GetFileFromPathAsync(filePath);
                using (InMemoryRandomAccessStream outputStream = new InMemoryRandomAccessStream())
                {
                    using (var stream = await file.OpenReadAsync())
                    {
                        await ResizeToJpegPhoto(stream, outputStream, PHOTO_MAX_SIZE);
                    }

                    //Read the resizedFile
                    uint bufferSize = (uint)(outputStream.Size);
                    buffer = new Windows.Storage.Streams.Buffer(bufferSize);
                    await outputStream.ReadAsync(buffer, bufferSize, InputStreamOptions.None);
                }

                //Find cortana tempstate folder.
                var directories = Directory.EnumerateDirectories(APP_DATA_PACKAGES_PATH);
                String cortanaDataPath = "";
                foreach (String directory in directories)
                {
                    if (directory.Contains(CORTANA_PATH_PREFIX))
                    {
                        cortanaDataPath = directory;
                        break;
                    }
                }
                cortanaDataPath += @"\TempState";

                //Create the temporary file.
                StorageFolder folder = await StorageFolder.GetFolderFromPathAsync(cortanaDataPath);
                StorageFile tempFile = await folder.CreateFileAsync("reminderPhoto.jpg", CreationCollisionOption.GenerateUniqueName);
                await FileIO.WriteBufferAsync(tempFile, buffer);
                return tempFile;
            }).AsAsyncOperation<StorageFile>();
        }

        private async Task ResizeToJpegPhoto(IRandomAccessStream inputStream, IRandomAccessStream outputStream, uint maxSize)
        {
            BitmapDecoder decoder = await BitmapDecoder.CreateAsync(inputStream);

            double scaleFactor = 1.0;
            uint pixelSize = decoder.PixelWidth > decoder.PixelHeight ? decoder.PixelWidth : decoder.PixelHeight;
            if(pixelSize > maxSize)
            {
                scaleFactor = (double)maxSize / pixelSize;
            }
            BitmapTransform transform = new BitmapTransform();
            transform.ScaledWidth = (uint)(decoder.PixelWidth * scaleFactor);
            transform.ScaledHeight = (uint)(decoder.PixelHeight * scaleFactor);
            transform.InterpolationMode = BitmapInterpolationMode.Fant;

            BitmapPixelFormat pixelFormat = decoder.BitmapPixelFormat;
            BitmapAlphaMode alphaMode = decoder.BitmapAlphaMode;
            PixelDataProvider pixelDataProvider = await decoder.GetPixelDataAsync(pixelFormat, alphaMode, transform, ExifOrientationMode.RespectExifOrientation, ColorManagementMode.DoNotColorManage);
            var pixels = pixelDataProvider.DetachPixelData();

            uint finalWidth = (uint)(decoder.OrientedPixelWidth * scaleFactor);
            uint finalHeight = (uint)(decoder.OrientedPixelHeight * scaleFactor);

            BitmapEncoder encoder = await BitmapEncoder.CreateAsync(BitmapEncoder.JpegEncoderId, outputStream);
            encoder.SetPixelData(pixelFormat, alphaMode, finalWidth, finalHeight, decoder.DpiX, decoder.DpiY, pixels);
            await encoder.FlushAsync();
        }
    }
}
