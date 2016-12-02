using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace BrokeredComponent1
{
    public sealed class Component1
    {
        [DllImport("user32")]
        internal static extern void LockWorkStation();

        public void Lock()
        {
            bool ret = NativeMethods.LockWorkStation();
            var result = NativeMethods.GetLastError();

        }
    }
}
