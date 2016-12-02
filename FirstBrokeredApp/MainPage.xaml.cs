using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Storage;
using Windows.System;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

namespace FirstBrokeredApp
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        public MainPage()
        {
            this.InitializeComponent();
        }

        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
            base.OnNavigatedTo(e);
        }

        private async void Button_Click(object sender, RoutedEventArgs e)
        {
            //BrokeredComponent1.Component1 broker = new BrokeredComponent1.Component1();
            //broker.Lock();
            //BrokeredComponent1.FileGenerator fileGenerator = new BrokeredComponent1.FileGenerator();
            //fileGenerator.GenerateTemparoryFileForCortana();
            BrokeredComponent1.FileGenerator fileGenerator = new BrokeredComponent1.FileGenerator();
            StorageFile file = await fileGenerator.GenerateTemparoryFileForCortana(@"C:\Users\ranbi\AppData\Local\Packages\fb017796-5e70-4f14-bfa4-4fa0b933b3b1_66gzgs4jj2sst\LocalState\build.jpg");

            String uri = @"ms-cortana://reminders/create?CallerPfn=Microsoft.Cortana_8wekyb3d8bbwe&photo.file=";
            uri += Uri.EscapeUriString(file.Path);
            fileGenerator.LaunchUri(uri);
            //LauncherOptions options = new LauncherOptions();
            //options.TreatAsUntrusted = false;
            //options.DisplayApplicationPicker = false;
            //await Launcher.LaunchUriAsync(new Uri(uri));
        }
    }
}
